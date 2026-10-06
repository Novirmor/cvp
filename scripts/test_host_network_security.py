#!/usr/bin/env python3
import base64
import configparser
import copy
import getpass
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import jinja2
from jinja2.nativetypes import NativeEnvironment
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible/roles"
ENV = NativeEnvironment(undefined=jinja2.StrictUndefined)
ENV.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
ENV.filters["b64decode"] = lambda value: base64.b64decode(value).decode()
ENV.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)


def load_tasks(role, file="main.yml"):
    return yaml.safe_load((ROLES / role / "tasks" / file).read_text())


def task_named(role, name, file="main.yml"):
    return copy.deepcopy(next(task for task in load_tasks(role, file) if task["name"] == name))


def defaults(role):
    return yaml.safe_load((ROLES / role / "defaults/main.yml").read_text())


def resolve(values):
    values = copy.deepcopy(values)
    for _ in range(30):
        changed = False
        for key, value in values.items():
            if isinstance(value, str) and "{{" in value:
                try:
                    rendered = ENV.from_string(value).render(values)
                except jinja2.UndefinedError:
                    continue
                if value != rendered:
                    values[key] = rendered
                    changed = True
        if not changed:
            return values
    raise AssertionError("Unresolved recursive defaults")


def render(role, template, values):
    return str(ENV.from_string((ROLES / role / "templates" / template).read_text()).render(values))


CLOUDFLARE_V4 = "173.245.48.10"
CLOUDFLARE_V6 = "2606:4700::10"


class Ruleset:
    def __init__(self, text):
        self.chains = {}
        chain = None
        for line in text.splitlines():
            line = line.strip()
            match = re.fullmatch(r"chain (\w+) \{", line)
            if match:
                chain = {"rules": [], "policy": "return"}
                self.chains[match[1]] = chain
            elif line == "}":
                chain = None
            elif chain is not None and line and not line.startswith("#"):
                if line.startswith("type "):
                    policy = re.search(r"policy (\w+);", line)
                    if policy is None:
                        raise AssertionError(f"Missing base-chain policy: {line}")
                    chain["policy"] = policy.group(1)
                else:
                    lexer = shlex.shlex(line, posix=True, punctuation_chars="{},;")
                    lexer.whitespace_split = True
                    chain["rules"].append(list(lexer))

    @staticmethod
    def values(tokens, index):
        if tokens[index] == "{":
            end = tokens.index("}", index)
            result = [token for token in tokens[index + 1:end] if token != ","]
            if not result:
                raise AssertionError("Empty anonymous nftables set")
            return result, end + 1
        result = [tokens[index]]
        index += 1
        while index < len(tokens) and tokens[index] == ",":
            result.append(tokens[index + 1])
            index += 2
        return result, index

    def verdict(self, name, packet):
        for tokens in self.chains[name]["rules"]:
            index = 0
            matches = True
            while index < len(tokens):
                token = tokens[index]
                if token in ("accept", "drop", "return"):
                    if matches:
                        return token
                    break
                if token == "jump":
                    if matches:
                        verdict = self.verdict(tokens[index + 1], packet)
                        if verdict != "return":
                            return verdict
                    break
                family = None
                address = False
                if token == "iifname":
                    value = packet["iif"]
                    index += 1
                elif tokens[index:index + 2] == ["ct", "state"]:
                    value = packet.get("state", "new")
                    index += 2
                elif tokens[index:index + 2] == ["ct", "status"]:
                    value = "dnat" if packet.get("dnat", False) else "none"
                    index += 2
                elif tokens[index:index + 2] == ["ct", "original"]:
                    if tokens[index + 2] == "proto-dst":
                        value = str(packet.get("original_port", packet.get("dport", 0)))
                        index += 3
                    else:
                        family = tokens[index + 2]
                        if tokens[index + 3] != "daddr":
                            raise AssertionError(tokens)
                        value = packet.get("original_address", packet.get("daddr", "192.0.2.10"))
                        address = True
                        index += 4
                elif tokens[index:index + 2] == ["meta", "l4proto"]:
                    value = packet.get("proto", "tcp")
                    index += 2
                elif token in ("tcp", "udp"):
                    matches &= packet.get("proto", "tcp") == token
                    value = str(packet.get(tokens[index + 1], 0))
                    index += 2
                elif token in ("ip", "ip6"):
                    family = token
                    if tokens[index + 1] == "protocol":
                        value = packet.get("proto", "tcp")
                    elif tokens[index + 1] == "saddr":
                        value = packet.get("saddr", "198.51.100.9")
                        address = True
                    else:
                        raise AssertionError(tokens)
                    index += 2
                else:
                    raise AssertionError(f"Unrecognized nftables expression: {tokens[index:]}")
                permitted, index = self.values(tokens, index)
                if family:
                    matches &= packet.get("family", "ip") == family
                if address:
                    matches &= any(ipaddress.ip_address(value) in ipaddress.ip_network(item) for item in permitted)
                else:
                    matches &= value in permitted
        return self.chains[name]["policy"]


class FirewallTests(unittest.TestCase):
    def values(self, ingress=True, **overrides):
        values = defaults("firewall") | {
            "inventory_hostname": "node1",
            "groups": {"ingress": ["node1"] if ingress else [], "k3s_servers": ["node1"]},
            "ansible_default_ipv4": {"interface": "eth0"},
            "ansible_default_ipv6": {"interface": "eth1"},
            "ansible_facts": {
                "eth0": {"ipv4": {"address": "192.0.2.10"}},
                "eth1": {"ipv6": [{"address": "2001:db8::10"}]},
            },
            "wireguard_interface": "wg0",
            "wireguard_port": 51820,
            "k3s_cluster_cidr": "10.42.0.0/16",
        }
        return resolve(values | overrides)

    def rules(self, **overrides):
        return Ruleset(render("firewall", "nftables.conf.j2", self.values(**overrides)))

    def test_public_forwarding_original_destination_and_port(self):
        rules = self.rules()
        packet = {"iif": "eth0", "dnat": True, "dport": 8000, "saddr": CLOUDFLARE_V4,
                  "original_address": "192.0.2.10", "original_port": 80}
        self.assertEqual(rules.verdict("forward", packet), "accept")
        cases = [
            {"original_port": 32080, "dport": 80},
            {"original_address": "10.43.0.80"},
            {"original_address": "192.0.2.11"},
            {"dnat": False, "daddr": "10.42.0.20", "dport": 80},
            {"proto": "udp"},
            {"saddr": "198.51.100.9"},
        ]
        for change in cases:
            with self.subTest(change=change):
                self.assertEqual(rules.verdict("forward", packet | change), "drop")
        self.assertEqual(self.rules(ingress=False).verdict("forward", packet), "drop")
        self.assertEqual(self.rules(firewall_public_ingress_ports=[]).verdict("forward", packet), "drop")
        ipv6 = packet | {"iif": "eth1", "family": "ip6", "saddr": CLOUDFLARE_V6,
                         "original_address": "2001:db8::10", "original_port": 443, "dport": 8443}
        self.assertEqual(rules.verdict("forward", ipv6), "accept")
        self.assertEqual(rules.verdict("forward", ipv6 | {"saddr": "2001:db8::20"}), "drop")

    def test_cluster_and_return_paths_survive(self):
        rules = self.rules(ingress=False)
        for interface in ("cni0", "flannel.1", "wg0", "tailscale0"):
            with self.subTest(interface=interface):
                packet = {"iif": interface, "dport": 5432}
                self.assertEqual(rules.verdict("forward", packet), "accept")
                self.assertEqual(rules.verdict("forward", packet | {"state": "invalid"}), "drop")
        for state in ("established", "related"):
            self.assertEqual(rules.verdict("forward", {"iif": "eth0", "state": state}), "accept")

    def test_dual_uplink_defaults_and_input_paths(self):
        values = self.values()
        self.assertEqual(values["firewall_external_ipv4_interface"], "eth0")
        self.assertEqual(values["firewall_external_ipv6_interface"], "eth1")
        self.assertEqual(values["firewall_external_interfaces"], ["eth0", "eth1"])
        rules = self.rules()
        for interface, source in (("eth1", CLOUDFLARE_V6), ("tailscale0", "fd7a:115c:a1e0::20")):
            for port in (80, 443):
                packet = {"iif": interface, "family": "ip6", "saddr": source, "dport": port}
                self.assertEqual(rules.verdict("input", packet), "accept")
                self.assertEqual(self.rules(ingress=False).verdict("input", packet), "drop")
        # Public HTTP(S) is the Cloudflare origin only.
        for packet in ({"iif": "eth1", "family": "ip6", "saddr": "2001:db8::20", "dport": 443},
                       {"iif": "eth0", "saddr": "198.51.100.9", "dport": 80}):
            self.assertEqual(rules.verdict("input", packet), "drop")
        self.assertEqual(rules.verdict("input", {"iif": "eth0", "saddr": CLOUDFLARE_V4, "dport": 443}), "accept")
        self.assertEqual(self.rules(firewall_public_ingress_ipv4_source_cidrs=[]).verdict(
            "input", {"iif": "eth0", "saddr": CLOUDFLARE_V4, "dport": 443}), "drop")
        self.assertEqual(rules.verdict("input", {
            "iif": "eth1", "family": "ip6", "saddr": "2001:db8::20", "proto": "udp", "dport": 51820,
        }), "accept")
        self.assertEqual(rules.verdict("input", {"iif": "eth0", "dport": 6443}), "drop")
        self.assertEqual(rules.verdict("input", {"iif": "wg0", "dport": 6443}), "accept")
        self.assertEqual(rules.verdict("input", {"iif": "tailscale0", "saddr": "100.64.0.20", "dport": 6443}), "accept")

    def test_ssh_is_public_only(self):
        rules = self.rules(firewall_ssh_ipv4_source_cidrs=["203.0.113.10/32"],
                           firewall_ssh_ipv6_source_cidrs=["2001:db8:5::10/128"])
        self.assertEqual(rules.verdict("input", {"iif": "eth0", "saddr": "203.0.113.10", "dport": 22}), "accept")
        self.assertEqual(rules.verdict("input", {"iif": "eth1", "family": "ip6", "saddr": "2001:db8:5::10",
                                                 "dport": 22}), "accept")
        for packet in ({"iif": "eth0", "saddr": "198.51.100.9", "dport": 22},
                       {"iif": "tailscale0", "saddr": "100.64.0.20", "dport": 22},
                       {"iif": "tailscale0", "saddr": "203.0.113.10", "dport": 22},
                       {"iif": "wg0", "saddr": "10.77.0.2", "dport": 22},
                       {"iif": "wg0", "saddr": "203.0.113.10", "dport": 22}):
            with self.subTest(packet=packet):
                self.assertEqual(rules.verdict("input", packet), "drop")

    def test_ipv6_control_traffic(self):
        rules = self.rules()
        packet = {"iif": "eth1", "family": "ip6", "saddr": "fe80::1", "proto": "udp", "sport": 547, "dport": 546}
        self.assertEqual(rules.verdict("input", packet), "accept")
        self.assertEqual(rules.verdict("input", packet | {"saddr": "2001:db8::1"}), "drop")
        self.assertEqual(self.rules(firewall_allow_dhcpv6=False).verdict("input", packet), "drop")
        self.assertEqual(rules.verdict("input", packet | {"proto": "ipv6-icmp", "nexthdr": "hopopts"}), "accept")

    def test_explicit_uplinks_and_secondary_addresses(self):
        values = self.values(firewall_external_ipv4_interface="ens3", firewall_external_ipv6_interface="ens4",
                             ansible_facts={"ens3": {"ipv4": {"address": "192.0.2.1"},
                                                    "ipv4_secondaries": [{"address": "192.0.2.2"}]}})
        self.assertEqual(values["firewall_public_ipv4_addresses"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(values["firewall_external_interfaces"], ["ens3", "ens4"])
        rules = Ruleset(render("firewall", "nftables.conf.j2", values))
        self.assertEqual(rules.verdict("forward", {
            "iif": "ens3", "dnat": True, "saddr": CLOUDFLARE_V4, "original_address": "192.0.2.2",
            "original_port": 443, "dport": 8443,
        }), "accept")

    def test_packaged_stop_override_preserves_other_owners(self):
        for role, name in (("base", "Install host prerequisites"), ("firewall", "Install nftables")):
            self.assertEqual(task_named(role, name)["ansible.builtin.apt"]["policy_rc_d"], 101)
        content = task_named("firewall", "Restrict nftables shutdown to the owned table")["ansible.builtin.copy"]["content"]
        commands = [["/usr/sbin/nft", "flush", "ruleset"]]
        for line in content.splitlines():
            if line.startswith("ExecStop="):
                command = line.split("=", 1)[1]
                if command:
                    commands.append(shlex.split(command.lstrip("-")))
                else:
                    commands = []
        tables = {("inet", "cvp_filter"), ("ip", "nat"), ("ip", "filter"), ("inet", "tailscale")}
        for command in commands:
            if command[1:] == ["flush", "ruleset"]:
                tables.clear()
            elif command[1:3] == ["delete", "table"]:
                tables.discard(tuple(command[3:]))
            else:
                self.fail(f"Unexpected stop command: {command}")
        self.assertEqual(tables, {("ip", "nat"), ("ip", "filter"), ("inet", "tailscale")})
        template_task = task_named("firewall", "Render the host firewall policy")["ansible.builtin.template"]
        self.assertEqual(shlex.split(template_task["validate"]), ["/usr/sbin/nft", "-c", "-f", "%s"])


class LocalAnsibleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cvp-network-security-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.environment = os.environ | {
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "ansible/collections"),
            "ANSIBLE_LOCAL_TEMP": str(self.directory / "controller"),
            "ANSIBLE_REMOTE_TEMP": str(self.directory / "modules"),
            "ANSIBLE_NOCOLOR": "1",
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "MOCK_STATE": str(self.directory / "state.json"),
            "MOCK_CALLS": str(self.directory / "calls.json"),
        }

    def executable(self, name, source):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + source)
        path.chmod(0o700)
        return path

    def test_api_certificate_covers_only_live_tailscale_addresses(self):
        self.executable("tailscale", "import os, sys\n"
                        "assert sys.argv[1:] == ['ip'], sys.argv\n"
                        "print(os.environ['MOCK_TAILSCALE_IPS'], end='')\n"
                        "sys.exit(int(os.environ.get('MOCK_TAILSCALE_RC', '0')))\n")
        tasks = [task_named("k3s_server", name) for name in (
            "Read this server's Tailscale addresses for the API certificate",
            "Cover the Tailscale addresses in the API certificate")]
        tasks.append({"ansible.builtin.copy": {"content": "{{ k3s_effective_tls_sans | to_json }}",
                                               "dest": str(self.directory / "sans.json")}})
        self.environment["MOCK_TAILSCALE_IPS"] = "100.100.100.20\nfd7a:115c:a1e0::5\n100.128.0.1\n10.0.0.1\nbad;x\n"
        for rc, expected in (("0", ["api.internal", "100.100.100.20", "fd7a:115c:a1e0::5"]), ("1", ["api.internal"])):
            with self.subTest(rc=rc):
                self.environment["MOCK_TAILSCALE_RC"] = rc
                self.play(tasks, {"k3s_tls_sans": ["api.internal"]})
                self.assertEqual(json.loads((self.directory / "sans.json").read_text()), expected)
        self.assertIn("k3s_effective_tls_sans", (ROLES / "k3s_server/templates/config.yaml.j2").read_text())

    def play(self, tasks, variables, success=True, module_defaults=None, check=False):
        play = [{"name": "Isolated host security regression", "hosts": "localhost", "connection": "local",
                 "become": False, "gather_facts": False, "vars": variables, "tasks": tasks,
                 "environment": {key: value for key, value in self.environment.items()
                                 if key.startswith("MOCK_") or key == "PATH"}}]
        if module_defaults:
            play[0]["module_defaults"] = module_defaults
        path = self.directory / "play.yml"
        path.write_text(yaml.safe_dump(play, sort_keys=False))
        result = subprocess.run(
            ["ansible-playbook", "-i", "localhost,", "-c", "local", str(path),
             "-e", "ansible_become=false", "-e", f"ansible_python_interpreter={sys.executable}"]
            + (["--check"] if check else []),
            env=self.environment, text=True, capture_output=True, timeout=90,
        )
        output = result.stdout + result.stderr
        self.assertNotIn("synthetic-auth-secret", output)
        self.assertEqual(result.returncode == 0, success, output)
        return output

    def mock_tailscale(self):
        self.executable("tailscale", r'''
import json
import os
from pathlib import Path
import stat
import sys
args = sys.argv[1:]
state_path = Path(os.environ["MOCK_STATE"])
state = json.loads(state_path.read_text()) if state_path.exists() else {}
if args[0] == "status":
    print(json.dumps({"BackendState": state.get("backend", "Running")}))
    sys.exit(0)
if args[0] == "up":
    auth_arg = next(arg for arg in args if arg.startswith("--auth-key="))
    assert auth_arg.startswith("--auth-key=file:")
    path = Path(auth_arg.removeprefix("--auth-key=file:"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.getuid()
    assert path.read_text() == "synthetic-auth-secret"
    state["auth_path"] = str(path)
    state["used_private_file"] = True
for arg in args:
    if arg.startswith("--advertise-tags="):
        state["tags"] = arg.split("=", 1)[1]
Path(os.environ["MOCK_CALLS"]).write_text(json.dumps(args))
state_path.write_text(json.dumps(state))
sys.exit(int(os.environ.get("MOCK_EXIT", "0")))
''')

    def test_tailscale_ssh_is_always_disabled(self):
        self.mock_tailscale()
        values = defaults("tailscale") | {"node_name": "test-node", "tailscale_auth_key": "synthetic-auth-secret",
                                        "tailscale_auth_key_temp_dir": str(self.directory)}
        self.play(load_tasks("tailscale", "enroll.yml"), values)
        self.assertEqual(json.loads(Path(self.environment["MOCK_CALLS"]).read_text())[-1], "--ssh=false")
        reconcile = [task_named("tailscale", "Keep Tailscale SSH disabled on enrolled hosts"),
                     task_named("tailscale", "Reconcile mutable Tailscale settings on an enrolled host")]
        status = {"rc": 0, "stdout": json.dumps({"BackendState": "Running"})}
        self.play(reconcile, values | {"tailscale_status": status})
        self.assertEqual(json.loads(Path(self.environment["MOCK_CALLS"]).read_text())[-1], "--ssh=false")
        Path(self.environment["MOCK_CALLS"]).unlink()
        for key, tasks in (("tailscale_extra_up_args", load_tasks("tailscale", "enroll.yml")),
                           ("tailscale_extra_set_args", reconcile)):
            for flag in ("--ssh", "--ssh=true", "-ssh"):
                with self.subTest(key=key, flag=flag):
                    self.play(tasks, values | {key: [flag], "tailscale_status": status}, success=False)
                    self.assertFalse(Path(self.environment["MOCK_CALLS"]).exists())

    def test_enrollment_secret_cleanup_success_and_failure(self):
        self.mock_tailscale()
        values = defaults("tailscale") | {"node_name": "test-node", "tailscale_auth_key": "synthetic-auth-secret",
                                        "tailscale_auth_key_temp_dir": str(self.directory)}
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code):
                self.environment["MOCK_EXIT"] = str(exit_code)
                self.play(load_tasks("tailscale", "enroll.yml"), values, success=exit_code == 0)
                state = json.loads(Path(self.environment["MOCK_STATE"]).read_text())
                self.assertTrue(state["used_private_file"])
                self.assertFalse(Path(state["auth_path"]).exists())
                self.assertEqual(list(self.directory.glob("cvp-tailscale-auth-*")), [])
                self.assertNotIn("synthetic-auth-secret", Path(self.environment["MOCK_CALLS"]).read_text())

    def test_enrollment_rejects_auth_key_extra_argument(self):
        self.mock_tailscale()
        values = defaults("tailscale") | {"node_name": "test-node", "tailscale_auth_key": "synthetic-auth-secret",
                                        "tailscale_auth_key_temp_dir": str(self.directory),
                                        "tailscale_extra_up_args": ["--auth-key=synthetic-auth-secret"]}
        self.play(load_tasks("tailscale", "enroll.yml"), values, success=False)
        self.assertFalse(Path(self.environment["MOCK_CALLS"]).exists())

    def test_empty_tags_revoke_previous_advertisement(self):
        self.mock_tailscale()
        state = Path(self.environment["MOCK_STATE"])
        state.write_text(json.dumps({"tags": "tag:k3s,tag:k3s-ingress"}))
        values = defaults("tailscale") | {
            "node_name": "test-node", "tailscale_advertise_tags": [],
            "tailscale_status": {"rc": 0, "stdout": '{"BackendState":"Running"}'},
        }
        self.play([task_named("tailscale", "Reconcile mutable Tailscale settings on an enrolled host")], values)
        self.assertEqual(json.loads(state.read_text())["tags"], "")

    def test_authorized_key_rotation_removes_old_and_preserves_complete_set(self):
        keys = []
        for name, algorithm in (("old", "ed25519"), ("new", "ed25519"), ("ecdsa", "ecdsa")):
            path = self.directory / name
            subprocess.run(["ssh-keygen", "-q", "-t", algorithm, "-N", "", "-f", str(path)], check=True)
            keys.append(path.with_suffix(".pub").read_text().strip())
        key_file = self.directory / "authorized_keys"
        key_file.write_text(keys[0] + "\n")
        tasks = load_tasks("base", "authorized-keys.yml")
        for task in tasks:
            self.assertTrue(any(action in task for action in (
                "ansible.builtin.assert", "ansible.builtin.command", "ansible.posix.authorized_key",
                "ansible.builtin.getent", "ansible.builtin.debug")))
            if "ansible.builtin.command" in task:
                self.assertEqual(task["ansible.builtin.command"]["argv"], ["ssh-keygen", "-l", "-f", "/dev/stdin"])
            if "ansible.posix.authorized_key" in task:
                self.assertNotIn("path", task["ansible.posix.authorized_key"])
        values = {"base_admin_user": getpass.getuser(), "base_admin_authorized_keys": keys[1:]}
        module_defaults = {"ansible.posix.authorized_key": {"path": str(key_file)}}
        self.play(tasks, values, module_defaults=module_defaults)
        self.assertNotIn(keys[0].split()[1], key_file.read_text())
        for key in keys[1:]:
            self.assertIn(key.split()[1], key_file.read_text())
        output = self.play(tasks, values, module_defaults=module_defaults)
        self.assertRegex(output, r"changed=0\s")
        before = key_file.read_text()
        for invalid in ([], ["ssh-ecdsa AAAA"], ["ssh-ed25519 AAAA"], [keys[1] + "\n" + keys[0]]):
            self.play(tasks, values | {"base_admin_authorized_keys": invalid}, success=False,
                      module_defaults=module_defaults)
            self.assertEqual(key_file.read_text(), before)

    def test_wireguard_rotation_is_confirmed_validated_and_atomic(self):
        self.executable("wg", r'''
import os
import sys
if sys.argv[1] == "pubkey":
    key = sys.stdin.read().strip()
    if key not in ("old-private", "new-private", "generated-private"):
        sys.exit(3)
    print(key.replace("private", "public"))
elif sys.argv[1] == "genkey":
    print("generated-private")
elif sys.argv[1] == "show":
    print(os.environ.get("MOCK_ACTIVE_KEY", ""))
else:
    sys.exit(4)
''')
        tasks = []
        for task in load_tasks("wireguard"):
            if task["name"] == "Render the owner-managed WireGuard mesh":
                break
            if task["name"] in ("Require WireGuard inventory data", "Require persisted public keys for every peer",
                                 "Install WireGuard tools", "Create WireGuard directories", "Install the in-place WireGuard reconciler"):
                continue
            task = copy.deepcopy(task)
            self.assertTrue(any(action in task for action in (
                "ansible.builtin.assert", "ansible.builtin.stat", "ansible.builtin.slurp",
                "ansible.builtin.command", "ansible.builtin.set_fact", "ansible.builtin.copy",
                "ansible.builtin.debug")))
            if "ansible.builtin.copy" in task:
                task["ansible.builtin.copy"]["owner"] = getpass.getuser()
                task["ansible.builtin.copy"]["group"] = grp.getgrgid(os.getgid()).gr_name
            tasks.append(task)
        key_file = self.directory / "privatekey"
        values = defaults("wireguard") | {
            "wireguard_private_key_file": str(key_file), "wireguard_private_key": "new-private",
            "wireguard_public_key": "new-public", "wireguard_rotation_confirm": "localhost",
        }
        scenarios = [
            ("old-private", {}, False, "old-private"),
            ("old-private", {"wireguard_public_key": "old-public"}, True, "old-private"),
            ("old-private", {"wireguard_rotate_private_key": True}, True, "new-private"),
            ("old-private", {"wireguard_rotate_private_key": True, "wireguard_rotation_confirm": "other"}, False, "old-private"),
            ("old-private", {"wireguard_rotate_private_key": True, "wireguard_public_key": "wrong-public"}, False, "old-private"),
            (None, {"wireguard_rotate_private_key": True, "wireguard_public_key": "wrong-public"}, False, None),
            (None, {"wireguard_rotate_private_key": True}, True, "new-private"),
            (None, {"wireguard_public_key": "old-public"}, True, "old-private"),
        ]
        self.environment["MOCK_ACTIVE_KEY"] = "old-private"
        for initial, overrides, success, expected in scenarios:
            with self.subTest(initial=initial, overrides=overrides):
                key_file.unlink(missing_ok=True)
                if initial is not None:
                    key_file.write_text(initial + "\n")
                self.play(tasks, values | overrides, success=success)
                self.assertEqual(key_file.read_text().strip() if key_file.exists() else None, expected)
                if success:
                    self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)


class SSHAndIngressTests(unittest.TestCase):
    def test_main_sshd_template_precedence_and_idempotence(self):
        expression = (ROLES / "base/templates/sshd_config.j2").read_text()
        include = "Include /etc/ssh/sshd_config.d/00-cvp-hardening.conf\n"
        original = "PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n" + include
        def apply(text):
            return str(ENV.from_string(expression).render(
                base_sshd_main_config={"content": base64.b64encode(text.encode()).decode()}))
        actual = apply(original)
        self.assertEqual(actual, include + original.removesuffix(include))
        self.assertEqual(apply(actual), actual)

    def test_effective_sshd_validation_global_match_and_syntax_errors(self):
        with tempfile.TemporaryDirectory(prefix="cvp-sshd-validator-") as directory:
            path = Path(directory)
            mock = path / "sshd"
            mock.write_text(f"#!{sys.executable}\n" + r'''
import json
import os
from pathlib import Path
import sys
calls = Path(os.environ["MOCK_CALLS"])
with calls.open("a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
if "-t" in sys.argv:
    sys.exit(int(os.environ.get("MOCK_SYNTAX_EXIT", "0")))
policy = json.loads(os.environ["MOCK_POLICY"])
if "-C" in sys.argv and "user=root" in sys.argv[sys.argv.index("-C") + 1]:
    policy.update(json.loads(os.environ.get("MOCK_ROOT_POLICY", "{}")))
for key, value in policy.items():
    print(key, value)
''')
            mock.chmod(0o700)
            expected = {"passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                        "permitrootlogin": "without-password", "x11forwarding": "no",
                        "clientaliveinterval": "300", "clientalivecountmax": "2", "maxauthtries": "4"}
            calls = path / "calls.jsonl"
            env = os.environ | {"MOCK_CALLS": str(calls), "MOCK_POLICY": json.dumps(expected),
                                "CVP_SSH_CONNECTION": "198.51.100.20 40000 192.0.2.10 22"}
            command = [sys.executable, str(ROLES / "base/files/cvp-validate-sshd"), "--sshd", str(mock),
                       "--config", str(path / "config"), "--user", "ops", "--user", "root"]
            result = subprocess.run(command, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            invocations = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertIn("-t", invocations[0])
            contexts = [args[args.index("-C") + 1] for args in invocations if "-C" in args]
            self.assertEqual(set(contexts), {
                "user=ops,addr=198.51.100.20,host=198.51.100.20,laddr=192.0.2.10,lport=22",
                "user=root,addr=198.51.100.20,host=198.51.100.20,laddr=192.0.2.10,lport=22",
            })
            for key in expected:
                with self.subTest(key=key):
                    weakened = expected | {key: "unexpected"}
                    result = subprocess.run(command, env=env | {"MOCK_POLICY": json.dumps(weakened)}, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
            for overrides in ({"MOCK_ROOT_POLICY": '{"passwordauthentication":"yes"}'}, {"MOCK_SYNTAX_EXIT": "1"}):
                result = subprocess.run(command, env=env | overrides, capture_output=True)
                self.assertNotEqual(result.returncode, 0)

    def test_forwarder_bounds_and_non_root_capability(self):
        for port in (80, 443):
            values = defaults("ingress_v6") | {"ingress_v6_port": port}
            unit = configparser.ConfigParser(interpolation=None)
            unit.read_string(render("ingress_v6", "cvp-ingress-v6.service.j2", values))
            service = unit["Service"]
            argv = shlex.split(service["ExecStart"])
            listen = dict(option.split("=", 1) for option in argv[1].split(",")[1:] if "=" in option)
            self.assertGreater(int(listen["max-children"]), 0)
            self.assertGreater(int(service["TasksMax"]), int(listen["max-children"]))
            self.assertNotEqual(service["User"], "root")
            self.assertEqual(service["AmbientCapabilities"], "CAP_NET_BIND_SERVICE")
            self.assertEqual(service["CapabilityBoundingSet"], "CAP_NET_BIND_SERVICE")
            self.assertEqual(argv[2], f"TCP4:127.0.0.1:{port},connect-timeout=10")


def load_tests(loader, tests, pattern):
    from test_host_network_activation import activation_tests
    tests.addTest(activation_tests())
    return tests


if __name__ == "__main__":
    for binary in ("ansible-playbook", "ssh-keygen"):
        if not shutil.which(binary):
            sys.exit(f"Required test tool is unavailable: {binary}")
    unittest.main(verbosity=2)
