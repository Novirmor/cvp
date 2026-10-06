#!/usr/bin/env python3
import ctypes
import fcntl
import json
import os
from pathlib import Path
import secrets
import selectors
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = str(Path(__file__).resolve())
DEADLINE = 150
PORTS = (80, 443, 22, 6443, 10250, 2379, 2380, 30080, 18080)
PUBLIC = {4: "192.0.2.1", 6: "2001:db8:2::1"}
ALTERNATE = {4: "192.0.2.99", 6: "2001:db8:2::99"}
BACKEND = {4: "10.42.0.2", 6: "fd42::2"}
INTERNAL = {4: "10.44.0.1", 6: "fd44::1"}
REMOTE = {4: "192.0.2.2", 6: "2001:db8:2::2"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def identity(kind, pid: str | int = "self"):
    return os.stat(f"/proc/{pid}/ns/{kind}").st_ino


def verify_isolation(guard, pid: str | int = "self"):
    user = identity("user", pid)
    net = identity("net", pid)
    require(user != guard["host_user"] and net != guard["host_net"],
            "Refusing network operations: user/network namespace is not isolated")
    require(guard["uid"] > 0 and
            Path(f"/proc/{pid}/uid_map").read_text().split() == ["0", str(guard["uid"]), "1"],
            "Refusing network operations: expected only the unprivileged launcher uid mapped to root")
    require(Path(f"/proc/{pid}/gid_map").read_text().split() == ["0", str(guard["gid"]), "1"],
            "Refusing network operations: unexpected group mapping")
    with open(f"/proc/{pid}/ns/net", "rb") as handle:
        owner = fcntl.ioctl(handle.fileno(), 0xB701)  # NS_GET_USERNS
    try:
        require(os.fstat(owner).st_ino == user, "Network namespace belongs to another user namespace")
    finally:
        os.close(owner)
    if "sandbox_user" in guard:
        require(user == guard["sandbox_user"], "Unexpected sandbox user namespace")
    return net


def interrupted(signum, frame):
    raise RuntimeError(f"Interrupted by signal {signum} (deadline {DEADLINE}s)")


def lifetime(seconds):
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.alarm(seconds)


def parent_death_signal():
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0, "Cannot set parent-death cleanup")
    require(os.getppid() == parent, "Sandbox parent exited during startup")


def render():
    try:
        import jinja2
        from jinja2.nativetypes import NativeEnvironment
        import yaml
    except ImportError:
        executable = shutil.which("ansible-playbook")
        if not executable or os.environ.get("CVP_DATAPLANE_ANSIBLE_PYTHON"):
            raise RuntimeError("Jinja2/PyYAML required; run with the pinned Ansible Python (mise exec)")
        with Path(executable).resolve().open() as stream:
            shebang = stream.readline().strip()
        require(shebang.startswith("#!/"), "ansible-playbook needs an absolute Python shebang")
        interpreter = shlex.split(shebang[2:])
        require(Path(interpreter[0]).name.startswith("python"),
                "ansible-playbook must use its pinned Python interpreter directly")
        os.environ["CVP_DATAPLANE_ANSIBLE_PYTHON"] = "1"
        os.execv(interpreter[0], [*interpreter, "-B", SCRIPT, *sys.argv[1:]])
    environment = NativeEnvironment(undefined=jinja2.StrictUndefined)
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    role = ROOT / "ansible/roles/firewall"
    values = yaml.safe_load((role / "defaults/main.yml").read_text()) | {
        "inventory_hostname": "dataplane",
        "groups": {"ingress": ["dataplane"], "k3s_servers": ["dataplane"]},
        "ansible_default_ipv4": {"interface": "eth0"},
        "ansible_default_ipv6": {"interface": "eth1"},
        "ansible_facts": {
            "eth0": {"ipv4": {"address": PUBLIC[4]}},
            "eth1": {"ipv6": [{"address": PUBLIC[6]}]},
        },
        "wireguard_interface": "wg0", "wireguard_port": 51820,
        "k3s_cluster_cidr": "10.42.0.0/16",
        # The public peer stands in for both the Cloudflare edge and the operator's SSH source.
        "firewall_public_ingress_ipv4_source_cidrs": [f"{REMOTE[4]}/32"],
        "firewall_public_ingress_ipv6_source_cidrs": [f"{REMOTE[6]}/128"],
        "firewall_ssh_ipv4_source_cidrs": [f"{REMOTE[4]}/32"],
        "firewall_ssh_ipv6_source_cidrs": [f"{REMOTE[6]}/128"],
    }
    for _ in range(30):
        pending = [key for key, value in values.items() if isinstance(value, str) and "{{" in value]
        if not pending:
            break
        for key in pending:
            try:
                values[key] = environment.from_string(values[key]).render(values)
            except jinja2.UndefinedError:
                continue
    require(not any(isinstance(value, str) and "{{" in value for value in values.values()),
            "Could not resolve firewall defaults")
    require(values["firewall_external_interfaces"] == ["eth0", "eth1"],
            "Dual-uplink defaults did not render both public interfaces")
    template = environment.from_string((role / "templates/nftables.conf.j2").read_text())
    return {
        "ingress": str(template.render(values)),
        "non-ingress": str(template.render(values | {"groups": {"k3s_servers": ["dataplane"]}})),
        "empty-ports": str(template.render(values | {"firewall_public_ingress_ports": []})),
        "foreign-source": str(template.render(values | {
            "firewall_public_ingress_ipv4_source_cidrs": ["203.0.113.0/24"],
            "firewall_public_ingress_ipv6_source_cidrs": ["2001:db8:ff::/48"],
            "firewall_ssh_ipv4_source_cidrs": ["203.0.113.10/32"],
            "firewall_ssh_ipv6_source_cidrs": ["2001:db8:ff::10/128"],
        })),
    }


class Endpoint:
    def __init__(self):
        self.listeners = []
        self.connections = {}

    @staticmethod
    def echo(connection):
        with connection:
            connection.settimeout(DEADLINE)
            try:
                while data := connection.recv(4096):
                    connection.sendall(data)
            except OSError:
                pass

    def accept(self, listener):
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=self.echo, args=(connection,), daemon=True).start()

    def serve(self, ports):
        for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            for port in ports:
                listener = socket.socket(family, socket.SOCK_STREAM)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((address, port))
                listener.listen(32)
                self.listeners.append(listener)
                threading.Thread(target=self.accept, args=(listener,), daemon=True).start()

    @staticmethod
    def exchange(connection):
        payload = secrets.token_bytes(32)
        connection.sendall(payload)
        received = b""
        while len(received) < len(payload):
            data = connection.recv(len(payload) - len(received))
            require(data, "Echo server closed the connection")
            received += data
        require(received == payload, "TCP echo payload mismatch")

    def request(self, request):
        action = request["action"]
        if action == "serve":
            self.serve(request["ports"])
            return {"result": "ready"}
        if action == "exchange":
            self.exchange(self.connections[request["id"]])
            return {"result": "accepted"}
        require(action in ("probe", "open"), f"Unknown endpoint action: {action}")
        family = socket.AF_INET6 if ":" in request["address"] else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        connection.settimeout(1.2)
        try:
            try:
                connection.connect((request["address"], request["port"]))
            except socket.timeout:
                return {"result": "dropped"}
            self.exchange(connection)
            self.exchange(connection)
            if action == "open":
                self.connections[request["id"]] = connection
                connection = None
            return {"result": "accepted"}
        finally:
            if connection is not None:
                connection.close()


def peer():
    parent_death_signal()
    lifetime(DEADLINE - 5)
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
    guard = json.loads(os.environ["CVP_DATAPLANE_GUARD"])
    net = verify_isolation(guard)
    require(net != guard["sandbox_net"], "Peer did not enter a child network namespace")
    endpoint = Endpoint()
    print(json.dumps({"pid": os.getpid(), "net": net}), flush=True)
    for line in sys.stdin:
        try:
            result = endpoint.request(json.loads(line))
        except Exception as error:
            result = {"error": str(error)}
        print(json.dumps(result), flush=True)


class Sandbox:
    def __init__(self, guard):
        self.guard = guard
        self.net = verify_isolation(guard)
        self.guard |= {"sandbox_user": identity("user"), "sandbox_net": self.net}
        self.peers = {}
        self.endpoint = Endpoint()
        self.passed = 0
        self.temporary = tempfile.TemporaryDirectory(prefix="cvp-firewall-evidence-")
        self.config = Path(self.temporary.name) / "nftables.conf"
        self.record = Path(self.temporary.name) / "record.json"

    def command(self, *argv, target=None, text=None):
        require(verify_isolation(self.guard) == self.net, "Sandbox network namespace changed")
        if target:
            process, expected_net = self.peers[target]
            require(process.poll() is None, f"Peer {target} exited")
            require(verify_isolation(self.guard, process.pid) == expected_net,
                    f"Peer {target} network namespace changed")
            argv = ("nsenter", f"--net=/proc/{process.pid}/ns/net", "--", *argv)
        result = subprocess.run(argv, input=text, text=True, capture_output=True, timeout=8)
        require(result.returncode == 0,
                f"Command failed ({shlex.join(argv)}):\n{result.stdout}{result.stderr}")
        return result.stdout

    @staticmethod
    def receive(process):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(selector.select(8), "Peer RPC timed out")
        line = process.stdout.readline()
        require(line, f"Peer exited unexpectedly (status {process.poll()})")
        result = json.loads(line)
        require("error" not in result, f"Peer error: {result.get('error')}")
        return result

    def request(self, target, **request):
        if target == "host":
            return self.endpoint.request(request)
        process, _ = self.peers[target]
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        return self.receive(process)

    def check(self, name, condition):
        require(condition, f"FAIL: {name}")
        self.passed += 1
        print(f"PASS: {name}", flush=True)

    def add_peer(self, name, interface, addresses):
        environment = os.environ | {"CVP_DATAPLANE_GUARD": json.dumps(self.guard)}
        process = subprocess.Popen(
            ["unshare", "--net", "--", sys.executable, "-B", SCRIPT, "--peer"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=environment,
        )
        self.peers[name] = (process, None)
        ready = self.receive(process)
        net = verify_isolation(self.guard, process.pid)
        require(ready == {"pid": process.pid, "net": net} and net != self.net,
                f"Peer {name} failed isolation handshake")
        require(net not in [value[1] for value in self.peers.values()], "Peers share a network namespace")
        self.peers[name] = (process, net)
        self.fresh(name)
        self.command("ip", "link", "add", interface, "type", "veth", "peer", "name", "remote")
        self.command("ip", "link", "set", "remote", "netns", str(process.pid))
        self.command("ip", "link", "set", interface, "up")
        self.command("ip", "link", "set", "remote", "up", target=name)
        for host, remote, prefix in addresses:
            for address, device, target in ((host, interface, None), (remote, "remote", name)):
                self.command("ip", "address", "add", f"{address}/{prefix}", "dev", device,
                             *(["nodad"] if ":" in address else []), target=target)
            self.command("ip", "-6" if ":" in host else "-4", "route", "add", "default",
                         "via", host, "dev", "remote", target=name)

    def fresh(self, target=None):
        links = json.loads(self.command("ip", "-j", "link", "show", target=target))
        require([link["ifname"] for link in links] == ["lo"], "New namespace has unexpected links")
        tables = json.loads(self.command("nft", "-j", "list", "tables", target=target))
        require(not any("table" in item for item in tables["nftables"]),
                "New namespace has unexpected nftables tables")
        self.command("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=0",
                     "net.ipv6.conf.default.disable_ipv6=0", "net.ipv6.conf.default.accept_dad=0", target=target)
        self.command("ip", "link", "set", "lo", "up", target=target)

    def nft(self, text, check=False):
        self.command("nft", *(["-c"] if check else []), "-f", "-", text=text)

    def table(self, name):
        data = json.loads(self.command("nft", "-j", "list", "table", "inet", name))
        return [item for item in data["nftables"] if "metainfo" not in item]

    def counters(self):
        return {item["counter"]["name"]: item["counter"]["packets"]
                for item in self.table("cvp_test_observe") if "counter" in item}

    def probe(self, name, source, address, port, accepted, hook, action="probe", **extra):
        before = self.counters()
        result = self.request(source, action=action, address=address, port=port, **extra)
        after = self.counters()
        expected = "accepted" if accepted else "dropped"
        require(result["result"] == expected,
                f"FAIL: {name}: expected {expected}, got {result}; hook counters {before} -> {after}")
        require(after[f"{hook}_before"] > before[f"{hook}_before"],
                f"FAIL: {name}: no SYN reached the {hook} hook")
        passed = after[f"{hook}_after"] - before[f"{hook}_after"]
        self.check(name, passed > 0 if accepted else passed == 0)

    def apply(self, rendered, variant, nat=False):
        names = ["cvp_test_unrelated"] + (["cvp_test_nat"] if nat else [])
        before = {name: self.table(name) for name in names}
        for iteration in (1, 2):
            self.config.write_text(rendered[variant])
            self.nft(rendered[variant], check=True)
            self.nft(rendered[variant])
            self.firewall_evidence("record")
            self.firewall_evidence("verify")
            self.check(f"{variant} grammar/apply/reload {iteration}; unrelated tables preserved",
                       all(self.table(name) == contents for name, contents in before.items()))

    def firewall_evidence(self, action):
        return self.command(sys.executable, "-B", str(ROOT / "ansible/roles/firewall/files/cvp-firewall-state"),
                            action, "--config", str(self.config), "--record", str(self.record),
                            "--nft", shutil.which("nft"))

    def require_evidence_failure(self, name):
        record = self.record.read_bytes()
        tables = self.command("nft", "-j", "list", "ruleset")
        try:
            self.firewall_evidence("verify")
        except RuntimeError:
            self.check(name, True)
        else:
            raise RuntimeError("Verification accepted firewall drift: " + name)
        self.check(name + " is read-only", record == self.record.read_bytes()
                   and tables == self.command("nft", "-j", "list", "ruleset"))

    def internal_paths(self, label):
        for version in (4, 6):
            source = f"public{version}"
            for port in (22, 6443, 10250, 2379, 2380):
                # WireGuard carries cluster traffic only; SSH is public-only.
                self.probe(f"{label} IPv{version} wg0 INPUT {port}", "internal", INTERNAL[version],
                           port, port != 22, "input")
            self.probe(f"{label} IPv{version} wg0 forwarding", "internal", BACKEND[version],
                       8080, True, "forward")
            self.probe(f"{label} IPv{version} public direct pod route blocked", source,
                       BACKEND[version], 80, False, "forward")
            result = self.request("host", action="probe", address=REMOTE[version], port=18080)
            self.check(f"{label} IPv{version} host egress + established INPUT reply",
                       result["result"] == "accepted")
            self.probe(f"{label} IPv{version} pod egress + established public FORWARD reply",
                        "backend", REMOTE[version], 18080, True, "forward")

    def admin_evidence(self):
        self.add_peer("tailscale", "tailscale0", [("100.64.0.10", "100.64.0.20", 24),
                                                 ("fd7a:115c:a1e0::10", "fd7a:115c:a1e0::20", 64)])
        script = (
            "import json, runpy, sys; module = runpy.run_path(sys.argv[1]); check = module['check']; "
            "original = check.__globals__['read_command']; "
            "check.__globals__['read_command'] = lambda argv: 'port ' + sys.argv[2] + '\\n' "
            "if argv == ['sshd', '-T'] else original(argv); print(json.dumps(check(json.load(sys.stdin))))"
        )
        for source, interface, host, client, family in (
            ("tailscale", "tailscale0", "100.64.0.10", "100.64.0.20", socket.AF_INET),
            ("tailscale", "tailscale0", "fd7a:115c:a1e0::10", "fd7a:115c:a1e0::20", socket.AF_INET6),
            ("internal", "wg0", INTERNAL[4], "10.44.0.2", socket.AF_INET),
        ):
            for bound, port in ((True, 2222), (False, 2223)):
                listener = socket.socket(family, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                if bound:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
                listener.bind((host, port))
                listener.listen(8)
                self.endpoint.listeners.append(listener)
                threading.Thread(target=self.endpoint.accept, args=(listener,), daemon=True).start()
                connection_id = host + str(port)
                result = self.request(source, action="open", address=host, port=port, id=connection_id)
                require(result["result"] == "accepted", "Private-interface TCP control connection failed")
                local = self.command("ss", "-H", "-tn", "state", "established")
                peer_port = None
                for line in local.splitlines():
                    fields = line.split()
                    if len(fields) == 4 and fields[2].endswith(":" + str(port)) and client in fields[3]:
                        peer_port = fields[3].rsplit(":", 1)[1]
                require(peer_port is not None, "Cannot find the isolated established TCP tuple")
                policy = {"firewall_ssh_port": port, "base_ssh_port": port,
                          "ipv4_source_cidrs": [], "ipv6_source_cidrs": [],
                          "ssh_connection": f"{client} {peer_port} {host} {port}",
                          "wireguard_address": INTERNAL[4]}
                try:
                    self.command(sys.executable, "-B", "-c", script,
                                 str(ROOT / "ansible/roles/firewall/files/cvp-admin-access-check"), str(port),
                                 text=json.dumps(policy))
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("An SSH session over Tailscale or WireGuard authorized activation")
                self.check(f"{interface} {'IPv6' if family == socket.AF_INET6 else 'IPv4'} "
                           f"{'bound' if bound else 'unbound'} private SSH rejected", True)
                if source == "tailscale" and family == socket.AF_INET and not bound:
                    result = self.request("public4", action="open", address=host, port=port, id="public-to-tailscale")
                    require(result["result"] == "accepted", "Public-to-private-address TCP control connection failed")
                    for line in self.command("ss", "-H", "-tn", "state", "established").splitlines():
                        fields = line.split()
                        if len(fields) == 4 and fields[2].endswith(":" + str(port)) and REMOTE[4] in fields[3]:
                            policy["ssh_connection"] = f"{REMOTE[4]} {fields[3].rsplit(':', 1)[1]} {host} {port}"
                            break
                    else:
                        raise RuntimeError("Public-to-private established socket was not observed")
                    try:
                        self.command(sys.executable, "-B", "-c", script,
                                     str(ROOT / "ansible/roles/firewall/files/cvp-admin-access-check"), str(port),
                                     text=json.dumps(policy))
                    except RuntimeError:
                        self.check("Public ingress to Tailscale destination rejected", True)
                    else:
                        raise RuntimeError("Public ingress was approved as a private SSH path")

    def run(self, rendered):
        self.fresh()
        print(f"Isolation verified: uid {self.guard['uid']} -> root, user={identity('user')}, net={self.net}", flush=True)
        self.command("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1",
                     "net.ipv6.conf.default.forwarding=1")
        self.add_peer("public4", "eth0", [(PUBLIC[4], REMOTE[4], 24)])
        self.add_peer("public6", "eth1", [(PUBLIC[6], REMOTE[6], 64)])
        self.add_peer("internal", "wg0", [(INTERNAL[4], "10.44.0.2", 24), (INTERNAL[6], "fd44::2", 64)])
        self.add_peer("backend", "cni0", [("10.42.0.1", BACKEND[4], 24), ("fd42::1", BACKEND[6], 64)])
        for version, interface, prefix in ((4, "eth0", 24), (6, "eth1", 64)):
            self.command("ip", "address", "add", f"{ALTERNATE[version]}/{prefix}", "dev", interface,
                         *(["nodad"] if version == 6 else []))
        self.endpoint.serve(PORTS)
        for name in self.peers:
            self.request(name, action="serve", ports=[80, 8080, 8443, 18080])
        self.nft('''table inet cvp_test_unrelated {
          set marker { type inet_service; elements = { 12345, 23456 }; }
          counter marker { packets 17 bytes 1234; }
          chain marker { tcp dport @marker counter name marker; }
        }
        table inet cvp_test_observe {
          counter input_before {}
          counter input_after {}
          counter forward_before {}
          counter forward_after {}
          chain input_before {
            type filter hook input priority -1; policy accept;
            tcp flags & (syn | ack) == syn counter name input_before
          }
          chain input_after {
            type filter hook input priority 1; policy accept;
            tcp flags & (syn | ack) == syn counter name input_after
          }
          chain forward_before {
            type filter hook forward priority -1; policy accept;
            tcp flags & (syn | ack) == syn counter name forward_before
          }
          chain forward_after {
            type filter hook forward priority 1; policy accept;
            tcp flags & (syn | ack) == syn counter name forward_after
          }
        }''')
        self.admin_evidence()
        for version in (4, 6):
            for port in PORTS:
                self.probe(f"control IPv{version} public INPUT listener {port}", f"public{version}",
                           PUBLIC[version], port, True, "input")
            self.probe(f"control IPv{version} public routed backend listener", f"public{version}",
                       BACKEND[version], 80, True, "forward")
        for variant in ("ingress", "non-ingress", "empty-ports", "foreign-source"):
            self.apply(rendered, variant)
            for version in (4, 6):
                for port in PORTS if variant in ("ingress", "foreign-source") else (22, 80, 443):
                    # The listed public source reaches SSH everywhere and HTTP(S) on the ingress node only.
                    accepted = variant != "foreign-source" and (
                        port == 22 or (variant == "ingress" and port in (80, 443)))
                    self.probe(f"{variant} IPv{version} public INPUT {port}", f"public{version}",
                               PUBLIC[version], port, accepted, "input")
            if variant not in ("empty-ports", "foreign-source"):
                self.internal_paths(variant)
        self.nft("delete table inet cvp_filter")
        rules = []
        for version, family in ((4, "ip"), (6, "ip6")):
            for original, translated in ((80, 8080), (443, 8443), (30080, 80)):
                destination = f"{BACKEND[version]}:{translated}" if version == 4 else f"[{BACKEND[version]}]:{translated}"
                rules.append(f'iifname "eth{version == 6:d}" {family} daddr '
                             f'{{ {PUBLIC[version]}, {ALTERNATE[version]} }} tcp dport {original} '
                             f'dnat {family} to {destination}')
        self.nft("table inet cvp_test_nat { chain prerouting { type nat hook prerouting priority dstnat; "
                 "policy accept;\n" + "\n".join(rules) + "\n}\n}\n")
        for version in (4, 6):
            for address, port in ((PUBLIC[version], 80), (PUBLIC[version], 443),
                                  (PUBLIC[version], 30080), (ALTERNATE[version], 80)):
                self.probe(f"control IPv{version} DNAT {address}:{port}", f"public{version}",
                           address, port, True, "forward")
        for variant in ("ingress", "non-ingress", "empty-ports", "foreign-source"):
            self.apply(rendered, variant, nat=True)
            if variant == "non-ingress":
                for version in (4, 6):
                    result = self.request(f"public{version}", action="exchange", id="persistent")
                    self.check(f"IPv{version} established DNAT session survives non-ingress reload",
                               result["result"] == "accepted")
            for version in (4, 6):
                for address, port in ((PUBLIC[version], 80), (PUBLIC[version], 443),
                                      (PUBLIC[version], 30080), (ALTERNATE[version], 80)):
                    accepted = variant == "ingress" and address == PUBLIC[version] and port in (80, 443)
                    self.probe(f"{variant} IPv{version} DNAT original {address}:{port}", f"public{version}",
                               address, port, accepted, "forward")
                if variant == "ingress":
                    self.probe(f"IPv{version} persistent DNAT session opened", f"public{version}",
                               PUBLIC[version], 80, True, "forward", action="open", id="persistent")
            if variant != "empty-ports":
                self.internal_paths(f"{variant}/DNAT")
        self.command("nft", "add", "rule", "inet", "cvp_filter", "output", "counter")
        self.require_evidence_failure("tampered owned rules detected")
        self.apply(rendered, "empty-ports", nat=True)
        self.config.write_text(self.config.read_text() + "\n# unapplied change\n")
        self.require_evidence_failure("unapplied config detected")
        self.config.write_text(rendered["empty-ports"])
        self.command("nft", "delete", "table", "inet", "cvp_filter")
        self.require_evidence_failure("absent owned table detected")
        self.apply(rendered, "empty-ports", nat=True)
        print(f"PASS: {self.passed} real-kernel checks; IPv4/IPv6 on separate uplinks", flush=True)

    def close(self):
        for process, _ in self.peers.values():
            if process.poll() is None:
                process.terminate()
        for process, _ in self.peers.values():
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()
        self.temporary.cleanup()


def sandbox():
    parent_death_signal()
    lifetime(DEADLINE - 10)
    data = json.load(sys.stdin)
    test = Sandbox(data["guard"])
    try:
        test.run(data["rendered"])
    finally:
        signal.alarm(0)
        test.close()


def main():
    require(sys.platform == "linux" and os.getuid() == os.geteuid() and os.getuid() > 0,
            "Run this integration check as an unprivileged user; never use sudo/root")
    for binary in ("unshare", "nsenter", "ip", "nft", "sysctl"):
        require(shutil.which(binary), f"Required integration-test tool unavailable: {binary}")
    rendered = render()
    guard = {"host_user": identity("user"), "host_net": identity("net"), "uid": os.getuid(), "gid": os.getgid()}
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    process = subprocess.Popen(
        ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable, "-B", SCRIPT, "--sandbox"],
        stdin=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        process.communicate(json.dumps({"guard": guard, "rendered": rendered}), timeout=DEADLINE)
        require(process.returncode == 0,
                f"Kernel dataplane check failed (exit {process.returncode}); unprivileged user/network "
                "namespaces, veth, IPv6, nftables and conntrack/NAT kernel support are required")
    finally:
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass
            if signum == signal.SIGTERM:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        process.wait(timeout=3)
    require(identity("user") == guard["host_user"] and identity("net") == guard["host_net"],
            "Launcher namespace identity unexpectedly changed")
    print("Sandbox process group cleaned up; launcher namespace identities unchanged", flush=True)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--sandbox"]:
            sandbox()
        elif sys.argv[1:] == ["--peer"]:
            peer()
        else:
            require(not sys.argv[1:], "Usage: python3 -B scripts/test-firewall-dataplane.py")
            main()
    except (Exception, KeyboardInterrupt) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
