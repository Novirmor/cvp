#!/usr/bin/env python3
"""Check CVP's LXC kernel prerequisites without changing the host.

Run on the candidate host: python3 - < scripts/host-readiness.py
Optional --functional attempts temporary devices and a bridged packet ONLY in
a new user/network namespace. It may cause the host kernel to autoload a module;
it never falls back to the host's network namespace if isolation is unavailable.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


MODULES = ("br_netfilter", "overlay", "vxlan")
HOST_SYSCTLS = ("net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables")
GUEST_SYSCTLS = ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
                 "net.ipv4.conf.all.src_valid_mark")


def run(*argv, timeout=10):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 125, "", str(exc)


def check_readiness():
    checks = []

    def add(name, passed, detail, required=True):
        checks.append({"name": name, "passed": bool(passed), "detail": detail,
                       "required": required})

    rc, virt, error = run("systemd-detect-virt")
    add("virtualization", rc == 0 and virt in ("lxc", "lxc-libvirt"), virt or error)
    add("architecture", os.uname().machine == "x86_64", os.uname().machine)

    cgroups = Path("/sys/fs/cgroup/cgroup.controllers")
    controllers = cgroups.read_text().split() if cgroups.exists() else []
    required = {"cpu", "memory", "pids"}
    add("cgroup v2 controllers", required.issubset(controllers), ", ".join(controllers) or "missing")
    subtree = Path("/sys/fs/cgroup/cgroup.subtree_control")
    add("cgroup delegation", subtree.exists() and os.access(subtree, os.W_OK), str(subtree))

    tun = Path("/dev/net/tun")
    add("TUN device", tun.exists() and stat.S_ISCHR(tun.stat().st_mode) and os.access(tun, os.W_OK),
        str(tun))
    filesystems = Path("/proc/filesystems").read_text()
    add("overlay filesystem", any(line.split()[-1] == "overlay" for line in filesystems.splitlines()),
        "registered in /proc/filesystems")

    for module in MODULES:
        path = Path("/sys/module") / module
        add(f"module {module}", path.is_dir(),
            f"{path} {'visible' if path.is_dir() else 'not visible (may be absent or hidden by LXC)'}",
            required=module != "br_netfilter")

    for key in HOST_SYSCTLS + GUEST_SYSCTLS:
        path = Path("/proc/sys") / key.replace(".", "/")
        if path.is_file():
            value = path.read_text().strip()
            passed = value == "1" if key in HOST_SYSCTLS else os.access(path, os.W_OK)
            detail = f"value={value}" if key in HOST_SYSCTLS else f"value={value}, writable={passed}"
        else:
            passed, detail = False, "missing"
        add(key, passed, detail)

    rc, routes, error = run("ip", "-6", "route", "show", "default")
    interfaces = {words[words.index("dev") + 1] for line in routes.splitlines()
                  if "dev" in (words := line.split()) and words.index("dev") + 1 < len(words)}
    if rc != 0:
        add("IPv6 default uplink", False, error)
    elif not interfaces:
        add("IPv6 default uplink", False, "no default route")
    for interface in sorted(interfaces):
        path = Path("/proc/sys/net/ipv6/conf") / interface / "accept_ra"
        add(f"IPv6 RA control ({interface})", path.is_file() and os.access(path, os.W_OK), str(path))

    return checks


CHILD = r'''
import json, os, socket, struct, subprocess, sys
parent_user, parent_net = map(int, sys.argv[1:])
if os.stat('/proc/self/ns/user').st_ino == parent_user or os.stat('/proc/self/ns/net').st_ino == parent_net:
    sys.exit('refusing test: user and network namespaces are not isolated')

def command(*argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip()[:300] or f'{argv[0]} failed')
    return result.stdout

def test_device(name, *argv):
    try:
        command(*argv)
        return {'name': name, 'passed': True, 'detail': 'device created'}
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return {'name': name, 'passed': False, 'detail': str(exc)}

def checksum(data):
    words = struct.unpack('!' + 'H' * (len(data) // 2), data)
    value = sum(words)
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff

def bridge_filter_test():
    name = 'bridged IPv4 netfilter hook'
    try:
        path = '/proc/sys/net/bridge/bridge-nf-call-iptables'
        if open(path).read().strip() != '1':
            raise RuntimeError('bridge-nf-call-iptables is not enabled in isolated namespace')
        for bridge_port, peer in (('cvp-br-a', 'cvp-tx'), ('cvp-br-b', 'cvp-rx')):
            command('ip', 'link', 'add', bridge_port, 'type', 'veth', 'peer', 'name', peer)
            command('ip', 'link', 'set', bridge_port, 'master', 'cvp-test-br')
            command('ip', 'link', 'set', bridge_port, 'up')
            command('ip', 'link', 'set', peer, 'up')
        command('ip', 'link', 'set', 'cvp-test-br', 'up')
        command('nft', 'add', 'table', 'ip', 'cvp_probe')
        command('nft', 'add', 'chain', 'ip', 'cvp_probe', 'forward',
                '{ type filter hook forward priority 0; policy accept; }')
        command('nft', 'add', 'rule', 'ip', 'cvp_probe', 'forward',
                'ip saddr 10.205.0.1 ip daddr 10.205.0.2 counter')

        source = socket.inet_aton('10.205.0.1')
        destination = socket.inet_aton('10.205.0.2')
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 42, 0, 64, 17, 0,
                             source, destination)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        frame = (b'\xff' * 6 + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' +
                 header + struct.pack('!HHHH', 12345, 23456, 8, 0))
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as receive:
            receive.bind(('cvp-rx', 0))
            receive.settimeout(3)
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as send:
                send.bind(('cvp-tx', 0))
                send.send(frame)
            seen = False
            while True:
                try:
                    if receive.recv(2048).startswith(frame):
                        seen = True
                        break
                except socket.timeout:
                    break

        state = json.loads(command('nft', '-j', 'list', 'chain', 'ip', 'cvp_probe', 'forward'))
        packets = [item['counter']['packets'] for entry in state['nftables']
                   for item in entry.get('rule', {}).get('expr', []) if 'counter' in item]
        passed = seen and any(count > 0 for count in packets)
        return {'name': name, 'passed': passed,
                'detail': f'frame crossed bridge={seen}, IPv4 forward counter={packets}'}
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return {'name': name, 'passed': False, 'detail': str(exc)}

results = [test_device('bridge creation', 'ip', 'link', 'add', 'cvp-test-br', 'type', 'bridge'),
           test_device('VXLAN creation', 'ip', 'link', 'add', 'cvp-test-vx', 'type', 'vxlan',
                       'id', '42', 'dstport', '4789', 'local', '127.0.0.1',
                       'remote', '127.0.0.2', 'dev', 'lo')]
if results[0]['passed']:
    results.append(bridge_filter_test())
print(json.dumps(results))
'''


def functional_test():
    user = os.stat("/proc/self/ns/user").st_ino
    net = os.stat("/proc/self/ns/net").st_ino
    rc, output, error = run("unshare", "--user", "--map-root-user", "--net",
                            sys.executable, "-c", CHILD, str(user), str(net), timeout=25)
    if rc:
        return None, error or output or f"unshare exited {rc}"
    try:
        return json.loads(output), ""
    except json.JSONDecodeError:
        return None, f"unexpected sandbox output: {output[:300]}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--functional", action="store_true",
                        help="opt-in isolated bridge/VXLAN and packet test; may autoload host modules")
    args = parser.parse_args()
    checks = check_readiness()
    for item in checks:
        status = "INFO" if not item.get("required", True) else "PASS" if item["passed"] else "FAIL"
        print(f"{status} {item['name']}: {item['detail']}")
    required = [item for item in checks if item.get("required", True)]
    print(f"CVP probe prerequisites: {sum(item['passed'] for item in required)}/{len(required)} passed")
    if args.functional:
        results, error = functional_test()
        if results is None:
            print(f"INCONCLUSIVE isolated functional test: {error}")
        else:
            for item in results:
                print(f"{'PASS' if item['passed'] else 'FAIL'} isolated {item['name']}: {item['detail']}")
            print("Note: this tests one synthetic packet, not multi-node K3s or real pod networking.")
    return 0 if all(item["passed"] for item in required) else 1


if __name__ == "__main__":
    sys.exit(main())
