#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import unittest


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/firewall"
HELPER = ROLE / "files/cvp-admin-access-check"
CONNECTION = "198.51.100.20 40000 192.0.2.10 22"
SOCKETS = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\n"


class AdminAccessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cvp-admin-access-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.calls = self.directory / "calls.jsonl"
        self.environment = os.environ | {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "SSH_CONNECTION": "",
            "CVP_TEST_CALLS": str(self.calls),
            "CVP_TEST_SSHD": "port 22\npasswordauthentication no\n",
            "CVP_TEST_SS": SOCKETS,
            "CVP_TEST_TAILSCALE": '{"BackendState":"Stopped"}',
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(self.directory / "controller"),
            "ANSIBLE_REMOTE_TEMP": str(self.directory / "modules"),
            "ANSIBLE_NOCOLOR": "1",
        }
        for name, args, variable in (
                ("sshd", ["-T"], "SSHD"),
                ("tailscale", ["status", "--json"], "TAILSCALE")):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n" +
                            "import json, os, sys\n" +
                            f"assert sys.argv[1:] == {args!r}, sys.argv\n" +
                            "with open(os.environ['CVP_TEST_CALLS'], 'a') as stream:\n"
                            "    stream.write(json.dumps(sys.argv) + '\\n')\n" +
                            f"print(os.environ['CVP_TEST_{variable}'], end='')\n" +
                            f"sys.exit(int(os.environ.get('CVP_TEST_{variable}_RC', '0')))\n")
            path.chmod(0o700)
        for name, source in {
            "ss": '''import json, os, sys
from pathlib import Path
if 'CVP_TEST_TOOLS_READY' in os.environ:
    assert Path(os.environ['CVP_TEST_TOOLS_READY']).is_file(), 'ss invoked before prerequisite installation'
with open(os.environ['CVP_TEST_CALLS'], 'a') as stream:
    stream.write(json.dumps(sys.argv) + '\\n')
if sys.argv[1:] == ['-H', '-ltn']:
    print(os.environ['CVP_TEST_SS'], end='')
    sys.exit(int(os.environ.get('CVP_TEST_SS_RC', '0')))
assert sys.argv[1:] == ['-H', '-tn', 'state', 'established']
if 'CVP_TEST_ESTABLISHED' in os.environ:
    print(os.environ['CVP_TEST_ESTABLISHED'], end='')
else:
    client, client_port, server, server_port = os.environ['CVP_TEST_CONNECTION'].split()
    interface = os.environ.get('CVP_TEST_BOUND', 'tailscale0' if server.startswith(('100.', 'fd7a:')) else 'wg0')
    local = server + ('%' + interface if interface else '')
    local = '[' + local + ']' if ':' in server else local
    peer = '[' + client + ']' if ':' in client else client
    print('0 0 ' + local + ':' + server_port + ' ' + peer + ':' + client_port)
sys.exit(int(os.environ.get('CVP_TEST_ESTABLISHED_RC', '0')))
''',
            "ip": '''import json, os, sys
from pathlib import Path
with open(os.environ['CVP_TEST_CALLS'], 'a') as stream:
    stream.write(json.dumps(sys.argv) + '\\n')
if sys.argv[1:] == ['link']:
    sys.exit(0)
if 'CVP_TEST_TOOLS_READY' in os.environ:
    assert Path(os.environ['CVP_TEST_TOOLS_READY']).is_file(), 'ip invoked before prerequisite installation'
client, client_port, server, server_port = os.environ['CVP_TEST_CONNECTION'].split()
family = '-6' if ':' in client else '-4'
assert sys.argv[1:] == [family, '-j', 'route', 'get', client, 'from', server,
                       'ipproto', 'tcp', 'sport', server_port, 'dport', client_port]
interface = 'tailscale0' if client.startswith(('100.', 'fd7a:')) else 'wg0'
print(os.environ.get('CVP_TEST_ROUTE', json.dumps([{'dst': client, 'dev': interface, 'flags': []}])))
sys.exit(int(os.environ.get('CVP_TEST_ROUTE_RC', '0')))
''',
        }.items():
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n" + source)
            path.chmod(0o700)
        self.policy = {
            "firewall_ssh_port": 22, "base_ssh_port": 22,
            "ipv4_source_cidrs": ["198.51.100.20/32"], "ipv6_source_cidrs": [],
            "ssh_connection": CONNECTION, "tailscale_rc": 0,
            "tailscale_status": '{"BackendState":"Stopped"}',
            "wireguard_address": "10.20.0.10", "wireguard_peer_addresses": ["10.20.0.20"],
        }

    def helper(self, overrides=None, success=True, raw=None) -> Any:
        policy = self.policy | (overrides or {})
        result = subprocess.run(
            [sys.executable, str(HELPER)], env=self.environment | {
                "CVP_TEST_CONNECTION": str(policy.get("ssh_connection") or self.environment["SSH_CONNECTION"])},
            input=json.dumps(policy) if raw is None else raw,
            text=True, capture_output=True, timeout=40,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        if success:
            return json.loads(result.stdout)
        self.assertIn("Administration-path preflight failed:", result.stderr)
        return result.stderr

    def test_local_port_and_exact_effective_port_list(self):
        self.assertEqual(self.helper()["path"], "source-cidr")
        for effective in ("port 2222\n", "port 22\nport 2222\n", "port 22\nport 22\n"):
            with self.subTest(effective=effective):
                self.environment["CVP_TEST_SSHD"] = effective
                self.helper(success=False)
        self.environment["CVP_TEST_SSHD"] = "port 22\n"
        self.environment["CVP_TEST_SS"] = SOCKETS.replace(":22", ":2222")
        self.assertIn("No actual TCP listener", self.helper(success=False))
        self.environment["CVP_TEST_SS"] = SOCKETS
        self.helper({"base_ssh_port": 2222}, success=False)
        self.helper({"ssh_connection": CONNECTION.removesuffix("22") + "2222"}, success=False)
        self.helper({"ssh_connection": "198.51.100.20 40000 192.0.2.11 22"})
        self.environment["CVP_TEST_SS"] = "LISTEN 0 128 192.0.2.10:22 0.0.0.0:*\n"
        self.helper({"ssh_connection": "198.51.100.20 40000 192.0.2.11 22"}, success=False)

    def test_custom_port_is_host_local(self):
        self.environment["CVP_TEST_SSHD"] = "port 2222\n"
        self.environment["CVP_TEST_SS"] = SOCKETS.replace(":22", ":2222")
        result = self.helper({"firewall_ssh_port": 2222, "base_ssh_port": 2222,
                              "ssh_connection": CONNECTION.removesuffix("22") + "2222"})
        self.assertEqual(result["port"], 2222)

    def test_fail_closed_policy_and_command_output(self):
        invalid = [
            {"firewall_ssh_port": value} for value in (0, 65536, True, 22.0, "22; accept", None)
        ] + [
            {"ipv4_source_cidrs": value} for value in ("198.51.100.20/32", {}, ["bad"],
                                                       ["198.51.100.20"], ["::/0"], ["192.0.2.1/24"])
        ] + [
            {"ssh_connection": value} for value in ("garbage", "host 10 192.0.2.10 22",
                                                     "198.51.100.20 0 192.0.2.10 22", 22)
        ] + [{"tailscale_status": value} for value in ("garbage", "[]", "{}", '{"BackendState":"Running","Self":null}')]
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                self.helper(overrides, success=False)
        for raw in ("{", "[]", "{}"):
            self.helper(raw=raw, success=False)
        for variable, bad_values in (
                ("SSHD", ("", "port nope\n", "port 22\nbroken\n", "PORT 22\n")),
                ("SS", ("", "garbage\n", "LISTEN 0 128 [:::22 [::]:*\n", SOCKETS + "bad\n"))):
            original = self.environment[f"CVP_TEST_{variable}"]
            for value in bad_values:
                with self.subTest(variable=variable, value=value):
                    self.environment[f"CVP_TEST_{variable}"] = value
                    self.helper(success=False)
            self.environment[f"CVP_TEST_{variable}"] = original
            self.environment[f"CVP_TEST_{variable}_RC"] = "1"
            self.helper(success=False)
            del self.environment[f"CVP_TEST_{variable}_RC"]

    def test_running_tailscale_does_not_protect_public_session(self):
        private = {"ipv4_source_cidrs": [], "tailscale_status": json.dumps({
            "BackendState": "Running", "Self": {"TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::10"]},
            "Peer": {"other": {"TailscaleIPs": ["100.64.0.11"]}},
        })}
        self.helper(private, success=False)
        self.helper({"ipv4_source_cidrs": ["198.51.100.21/32"]}, success=False)
        for destination, success in (("100.64.0.10", True), ("100.64.0.11", False)):
            result = self.helper(private | {"ssh_connection": f"100.64.0.20 40000 {destination} 22"}, success=success)
            if success:
                self.assertEqual(result["path"], "tailscale")
        self.assertEqual(self.helper(private | {
            "ssh_connection": "fd7a:115c:a1e0::20 40000 fd7a:115c:a1e0::10 22",
        })["path"], "tailscale")
        self.helper(private | {"tailscale_status": '{"BackendState":"Stopped","Self":{"TailscaleIPs":["100.64.0.10"]}}',
                               "ssh_connection": "100.64.0.20 40000 100.64.0.10 22"}, success=False)

    def test_wireguard_requires_exact_destination_and_authenticated_peer_address(self):
        private = {"ipv4_source_cidrs": [], "ssh_connection": "10.20.0.20 40000 10.20.0.10 22"}
        self.assertEqual(self.helper(private)["path"], "wireguard")
        for connection in ("10.20.0.21 40000 10.20.0.10 22", "10.20.0.20 40000 192.0.2.10 22"):
            self.helper(private | {"ssh_connection": connection}, success=False)

    def test_private_addresses_require_exact_bound_socket_and_matching_route(self):
        for client, server, interface, status in (
            ("100.64.0.20", "100.64.0.10", "tailscale0", {"BackendState": "Running", "Self": {"TailscaleIPs": ["100.64.0.10"]}}),
            ("fd7a:115c:a1e0::20", "fd7a:115c:a1e0::10", "tailscale0", {"BackendState": "Running", "Self": {"TailscaleIPs": ["fd7a:115c:a1e0::10"]}}),
            ("10.20.0.20", "10.20.0.10", "wg0", {"BackendState": "Stopped"}),
        ):
            policy = {"ipv4_source_cidrs": [], "ssh_connection": f"{client} 40000 {server} 22",
                      "tailscale_status": json.dumps(status)}
            with self.subTest(interface=interface, client=client):
                self.helper(policy)
                for bound in ("", "eth0", "lo"):
                    self.environment["CVP_TEST_BOUND"] = bound
                    self.assertIn("ingress is unproven", self.helper(policy, success=False))
                self.environment.pop("CVP_TEST_BOUND")
                local = f"[{server}%{interface}]:22" if ":" in server else f"{server}%{interface}:22"
                peer = f"[{client}]:40001" if ":" in client else f"{client}:40001"
                correct_peer = f"[{client}]:40000" if ":" in client else f"{client}:40000"
                correct = f"0 0 {local} {correct_peer}\n"
                for evidence in ("", "garbage", f"0 0 {local} {peer}\n", "0 0 invalid:22 invalid:40000", correct * 2):
                    self.environment["CVP_TEST_ESTABLISHED"] = evidence
                    self.helper(policy, success=False)
                self.environment.pop("CVP_TEST_ESTABLISHED")
                for route in ([], {}, [None], [{"dev": "eth0"}], [{"dev": interface, "gateway": "192.0.2.1"}],
                              [{"dev": interface, "type": "local"}], [{"dev": interface, "flags": ["linkdown"]}],
                              [{"dev": interface}, {"dev": interface}]):
                    self.environment["CVP_TEST_ROUTE"] = json.dumps(route)
                    self.helper(policy, success=False)
                self.environment["CVP_TEST_ROUTE"] = "not-json"
                self.helper(policy, success=False)
                self.environment.pop("CVP_TEST_ROUTE")
                for variable in ("CVP_TEST_ESTABLISHED_RC", "CVP_TEST_ROUTE_RC"):
                    self.environment[variable] = "1"
                    self.helper(policy, success=False)
                    self.environment.pop(variable)
                self.environment["CVP_TEST_ESTABLISHED"] = correct
                self.helper(policy)
                if ":" in server:
                    self.environment["CVP_TEST_ESTABLISHED"] = f"0 0 [{server}]%{interface}:22 {correct_peer}\n"
                    self.helper(policy)
                self.environment.pop("CVP_TEST_ESTABLISHED")

    def test_public_session_to_tailscale_address_is_not_private_ingress(self):
        self.environment["CVP_TEST_BOUND"] = ""
        self.helper({"ipv4_source_cidrs": [], "ssh_connection": "198.51.100.20 40000 100.64.0.10 22",
                     "tailscale_status": '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.10"]}}'},
                    success=False)

    def test_missing_connection_reports_limited_proof_and_keeps_bootstrap_gate(self):
        self.assertEqual(self.helper({"ssh_connection": ""})["path"], "connection-proof-unavailable")
        for status in ('{"BackendState":"Stopped"}', '{"BackendState":"Running"}'):
            error = self.helper({"ssh_connection": "", "ipv4_source_cidrs": [],
                                 "tailscale_status": status}, success=False)
            for marker in ("SSH_CONNECTION is unavailable", "firewall_ssh_ipv4_source_cidrs",
                           "firewall_ssh_ipv6_source_cidrs", "independently verified source", "Tailscale Running"):
                self.assertIn(marker, error)
        self.environment["SSH_CONNECTION"] = CONNECTION
        self.assertEqual(self.helper({"ssh_connection": ""})["path"], "source-cidr")

    def test_unbound_private_session_error_names_the_matching_source_cidr(self):
        self.environment["CVP_TEST_BOUND"] = ""
        for client, server, version, suffix in (("100.64.0.20", "100.64.0.10", 4, 32),
                                               ("fd7a:115c:a1e0::20", "fd7a:115c:a1e0::10", 6, 128)):
            policy = {"ipv4_source_cidrs": [], "ssh_connection": f"{client} 40000 {server} 22",
                      "tailscale_status": json.dumps({"BackendState": "Running", "Self": {"TailscaleIPs": [server]}})}
            error = self.helper(policy, success=False)
            for marker in ("stock unbound sshd", f"firewall_ssh_ipv{version}_source_cidrs",
                           f"{client}/{suffix}", "not its public egress IP"):
                self.assertIn(marker, error)
            self.assertEqual(self.helper(policy | {f"ipv{version}_source_cidrs": [f"{client}/{suffix}"]})["path"], "source-cidr")

    def play(self, overrides=None, success=True, check=False):
        source = (ROLE / "tasks/main.yml").read_text()
        prefix, separator, rest = source.partition("- name: Install nftables\n")
        self.assertTrue(separator)
        self.assertIn("Verify the candidate firewall administration path", prefix)
        self.assertNotIn("ansible.builtin.copy:", prefix)
        self.assertNotIn("ansible.builtin.template:", prefix)
        self.assertIn("Render the host firewall policy", rest)
        self.assertEqual(prefix.count("ansible.builtin.apt:"), 1)
        self.assertLess(prefix.index("Install administration preflight inspection tools"),
                        prefix.index("Verify the candidate firewall administration path"))
        prefix = prefix.replace("ansible.builtin.apt:", "cvp_prerequisites_stub:")
        actions = self.directory / "action_plugins"
        actions.mkdir(exist_ok=True)
        (actions / "cvp_prerequisites_stub.py").write_text(
            "import os\nfrom pathlib import Path\nfrom ansible.plugins.action import ActionBase\n"
            "class ActionModule(ActionBase):\n"
            "    def run(self, tmp=None, task_vars=None):\n"
            "        assert self._task.args == {'name': 'iproute2', 'state': 'present', 'update_cache': True, "
            "'cache_valid_time': 3600, 'policy_rc_d': 101}\n"
            "        Path(os.environ['CVP_TEST_TOOLS_READY']).write_text('ready')\n"
            "        return dict(changed=False)\n"
        )
        tools_ready = self.directory / "tools-ready"
        tools_ready.unlink(missing_ok=True)
        self.environment.update(ANSIBLE_ACTION_PLUGINS=str(actions), CVP_TEST_TOOLS_READY=str(tools_ready))
        fixture = self.directory / "role"
        (fixture / "tasks").mkdir(parents=True, exist_ok=True)
        (fixture / "files").mkdir(exist_ok=True)
        shutil.copyfile(HELPER, fixture / "files/cvp-admin-access-check")
        include = fixture / "tasks/preflight.yml"
        include.write_text(prefix)
        marker = self.directory / "mutation"
        marker.unlink(missing_ok=True)
        self.calls.unlink(missing_ok=True)
        variables = {
            "firewall_manage": True, "firewall_ssh_port": 22, "base_ssh_port": 22,
            "firewall_ssh_ipv4_source_cidrs": ["198.51.100.20/32"], "firewall_ssh_ipv6_source_cidrs": [],
            "ansible_env": {"SSH_CONNECTION": CONNECTION}, "ansible_port": 22000,
            "firewall_external_interfaces": ["fixture0"], "ansible_interfaces": ["lo", "fixture0"],
            "wireguard_interface": "wg0", "wireguard_address": "10.20.0.10",
        } | (overrides or {})
        self.environment["CVP_TEST_CONNECTION"] = variables["ansible_env"].get("SSH_CONNECTION") or self.environment["SSH_CONNECTION"]
        play = [{"hosts": "localhost", "connection": "local", "become": False,
                 "gather_facts": False, "vars": variables,
                 "environment": {key: value for key, value in self.environment.items()
                                 if key.startswith("CVP_TEST_") or key in ("PATH", "SSH_CONNECTION")},
                 "tasks": [{"ansible.builtin.include_tasks": str(include)},
                           {"ansible.builtin.copy": {"content": "mutation reached\n", "dest": str(marker), "mode": "0600"},
                            "when": "not ansible_check_mode"}]}]
        play_path = self.directory / "play.json"
        play_path.write_text(json.dumps(play))
        inventory = self.directory / "inventory.json"
        inventory.write_text(json.dumps({"all": {"hosts": {"localhost": {}}, "children": {
            "wireguard": {"hosts": {"controller": {"wireguard_address": "10.20.0.20"}}},
        }}}))
        result = subprocess.run(
            ["ansible-playbook", "-i", str(inventory), str(play_path),
             "-e", f"ansible_python_interpreter={sys.executable}"] + (["--check"] if check else []),
            env=self.environment, capture_output=True, text=True, timeout=90,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, success, output)
        self.assertEqual(marker.exists(), success and not check, output)
        self.assertTrue(tools_ready.is_file(), output)
        calls = [json.loads(line)[1:] for line in self.calls.read_text().splitlines()]
        self.assertEqual(calls.count(["status", "--json"]), 1)
        connection = self.environment["CVP_TEST_CONNECTION"].split()
        allowed = [["link"], ["status", "--json"], ["-T"], ["-H", "-ltn"], ["-H", "-tn", "state", "established"]]
        if connection:
            client, client_port, server, server_port = connection
            allowed.append(["-6" if ":" in client else "-4", "-j", "route", "get", client, "from", server,
                            "ipproto", "tcp", "sport", server_port, "dport", client_port])
        self.assertTrue(all(call in allowed for call in calls), calls)
        return output, calls

    def test_ansible_include_rejects_wrong_listener_before_mutation_and_accepts_nat(self):
        self.environment["CVP_TEST_SSHD"] = "port 2222\n"
        output, _ = self.play(success=False)
        self.assertIn("extra ports are unmodeled", output)
        self.environment["CVP_TEST_SSHD"] = "port 22\n"
        self.environment["CVP_TEST_SS"] = SOCKETS.replace(":22", ":2222")
        output, _ = self.play(success=False)
        self.assertIn("No actual TCP listener", output)
        self.environment["CVP_TEST_SS"] = SOCKETS
        self.play()

    def test_ansible_include_checks_current_source_and_tailscale_self_destination(self):
        self.environment["CVP_TEST_TAILSCALE"] = '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.10"]}}'
        self.play({"firewall_ssh_ipv4_source_cidrs": []}, success=False)
        self.play({"firewall_ssh_ipv4_source_cidrs": [],
                   "ansible_env": {"SSH_CONNECTION": "100.64.0.20 40000 100.64.0.10 22"}})
        self.play({"firewall_ssh_ipv4_source_cidrs": ["garbage"]}, success=False)

    def test_ansible_check_executes_readonly_guards_and_recovers_unprivileged_session(self):
        self.environment["SSH_CONNECTION"] = CONNECTION
        output, calls = self.play({"ansible_env": {}}, check=True)
        self.assertIn("Read the remote SSH session before privilege escalation", output)
        self.assertIn(["-T"], calls)
        self.assertIn(["-H", "-ltn"], calls)
        self.assertNotRegex(output, r"changed=[1-9]")
        self.environment["SSH_CONNECTION"] = "198.51.100.21 40000 192.0.2.10 22"
        self.play({"ansible_env": {}}, check=True, success=False)
        self.environment["SSH_CONNECTION"] = ""
        self.play({"ansible_env": {}}, check=True)

    def test_ansible_include_allows_verified_wireguard_session_without_tailscale(self):
        self.play({"firewall_ssh_ipv4_source_cidrs": [],
                   "ansible_env": {"SSH_CONNECTION": "10.20.0.20 40000 10.20.0.10 22"}})
        self.environment["CVP_TEST_BOUND"] = ""
        self.play({"firewall_ssh_ipv4_source_cidrs": [],
                   "ansible_env": {"SSH_CONNECTION": "10.20.0.20 40000 10.20.0.10 22"}}, success=False)

    def test_ansible_caller_forwards_nondefault_wireguard_interface(self):
        self.environment["CVP_TEST_BOUND"] = "wgmesh"
        self.environment["CVP_TEST_ROUTE"] = '[{"dev":"wgmesh","flags":[]}]'
        for check in (False, True):
            self.play({"wireguard_interface": "wgmesh", "firewall_ssh_ipv4_source_cidrs": [],
                       "ansible_env": {"SSH_CONNECTION": "10.20.0.20 40000 10.20.0.10 22"}}, check=check)
        self.environment["CVP_TEST_BOUND"] = "wg0"
        self.play({"wireguard_interface": "wgmesh", "firewall_ssh_ipv4_source_cidrs": [],
                   "ansible_env": {"SSH_CONNECTION": "10.20.0.20 40000 10.20.0.10 22"}}, success=False)


if __name__ == "__main__":
    if not shutil.which("ansible-playbook"):
        sys.exit("Required test tool is unavailable: ansible-playbook")
    unittest.main(verbosity=2)
