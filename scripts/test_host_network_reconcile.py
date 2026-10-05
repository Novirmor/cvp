#!/usr/bin/env python3
import getpass
import grp
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import yaml

from test_host_network_security import LocalAnsibleTests, ROLES, defaults, load_tasks, task_named


class ServiceFixture(LocalAnsibleTests):
    def service_fixture(self):
        self.config = self.directory / "config"
        self.config.write_text("old\n")
        self.stamp = self.directory / "activation"
        self.state = Path(self.environment["MOCK_STATE"])
        self.state.write_text(json.dumps({"active": True, "invocation": 1, "applications": []}))
        self.environment["MOCK_CONFIG"] = str(self.config)
        collection = self.directory / "collections/ansible_collections/cvp_test/mock/plugins/modules"
        collection.mkdir(parents=True)
        (collection / "systemd_service.py").write_text(r'''
import json, os
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule
module = AnsibleModule(argument_spec={
    "name": {"type": "str"}, "state": {"type": "str"},
    "enabled": {"type": "bool"}, "daemon_reload": {"type": "bool"},
}, supports_check_mode=True)
path = Path(os.environ["MOCK_STATE"])
state = json.loads(path.read_text())
action = module.params["state"]
apply = action in ("restarted", "reloaded") or (action == "started" and not state["active"])
if apply and not module.check_mode:
    if os.environ.get("MOCK_FAIL") == "yes":
        module.fail_json(msg="Injected activation failure")
    state["active"] = True
    if action != "reloaded" and os.environ.get("MOCK_STALE_PROCESS") != "yes":
        state["invocation"] += 1
    state["live_config"] = Path(os.environ["MOCK_CONFIG"]).read_text()
    state["applications"].append(action)
    state["table"] = [{"table": {"family": "inet", "name": "cvp_filter", "handle": state["invocation"]}},
                      {"rule": {"family": "inet", "table": "cvp_filter", "expr": state["live_config"]}}]
    path.write_text(json.dumps(state))
module.exit_json(changed=apply, status={"ActiveState": "active" if state["active"] else "inactive",
                                       "InvocationID": str(state["invocation"]), "MainPID": "12345"})
''')
        self.environment["ANSIBLE_COLLECTIONS_PATH"] = str(self.directory / "collections") + os.pathsep + self.environment["ANSIBLE_COLLECTIONS_PATH"]
        self.executable("ss", 'import os\nprint("users:((socat,pid=" + os.environ.get("MOCK_LISTENER_PID", "12345") + ",fd=5))")\n')

    def relocate(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self.relocate(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {key: self.relocate(item) for key, item in value.items()}
        if "ansible.builtin.systemd_service" in result:
            result["cvp_test.mock.systemd_service"] = result.pop("ansible.builtin.systemd_service")
        for action in ("ansible.builtin.copy", "ansible.builtin.template"):
            if action in result:
                result[action]["owner"] = getpass.getuser()
                result[action]["group"] = grp.getgrgid(os.getgid()).gr_name
        return result


class ServiceActivationTests(ServiceFixture):
    def test_interrupted_and_failed_journal_ingress_activation_recovers(self):
        self.service_fixture()
        tasks = self.relocate(load_tasks("base", "activate-service.yml"))
        for unit, probe in (("systemd-journald.service", {}), ("ssh.service", {"_cvp_service_action": "reloaded"}),
                            ("cvp-ingress-v6-80.service", {"_cvp_service_probe_port": 80})):
            values = {"_cvp_service_unit": unit, "_cvp_service_inputs": [str(self.config)],
                      "_cvp_service_stamp": str(self.stamp)} | probe
            self.play(tasks, values)
            old_stamp = self.stamp.read_text()
            self.config.write_text(unit + " changed\n")
            failure = {"ansible.builtin.fail": {"msg": "Interrupted after file write"}}
            self.play([failure] + tasks, values, success=False)
            self.assertEqual(self.stamp.read_text(), old_stamp)
            self.play(tasks, values)
            self.assertEqual(json.loads(self.state.read_text())["live_config"], self.config.read_text())
            self.assertRegex(self.play(tasks, values), r"changed=0\s")
            self.config.write_text(unit + " second change\n")
            self.environment["MOCK_FAIL"] = "yes"
            self.play(tasks, values, success=False)
            self.assertFalse(self.stamp.exists())
            self.environment.pop("MOCK_FAIL")
            self.play(tasks, values)
            state = json.loads(self.state.read_text())
            count = len(state["applications"])
            state["invocation"] += 1
            self.state.write_text(json.dumps(state))
            self.play(tasks, values)
            self.assertEqual(len(json.loads(self.state.read_text())["applications"]), count + 1)
        self.environment["MOCK_LISTENER_PID"] = "54321"
        self.play(tasks, values, success=False)
        self.assertFalse(self.stamp.exists())
        self.environment.pop("MOCK_LISTENER_PID")
        self.play(tasks, values)
        self.assertTrue(self.stamp.exists())
        self.config.write_text("a newer ingress unit\n")
        self.environment["MOCK_STALE_PROCESS"] = "yes"
        self.play(tasks, values, success=False)
        self.assertFalse(self.stamp.exists())
        self.environment.pop("MOCK_STALE_PROCESS")
        self.play(tasks, values)

    def test_wireguard_role_never_restarts_an_existing_interface(self):
        self.service_fixture()
        helper = self.executable("wg-state", r'''
import json, os, sys
from pathlib import Path
with Path(os.environ["MOCK_CALLS"]).open("a") as stream:
    stream.write(sys.argv[1] + "\n")
print(json.dumps({"present": True, "matches": True, "changed": False}))
''')
        tasks = self.relocate(load_tasks("wireguard", "activate.yml"))
        values = defaults("wireguard") | {"wireguard_state_helper": str(helper),
                                          "wireguard_activation_stamp": str(self.stamp)}
        self.play(tasks, values)
        self.assertEqual(json.loads(self.state.read_text())["applications"], [])
        self.assertEqual(Path(self.environment["MOCK_CALLS"]).read_text().splitlines(), ["inspect", "apply"])
        self.state.write_text(json.dumps({"active": False, "invocation": 0, "applications": []}))
        self.play(tasks, values, success=False)
        self.assertEqual(json.loads(self.state.read_text())["applications"], [])


class FirewallActivationTests(ServiceFixture):
    def test_every_convergence_repairs_drift_and_verification_is_readonly(self):
        self.service_fixture()
        nft = self.executable("nft", r'''
import json, os, sys
from pathlib import Path
state = json.loads(Path(os.environ["MOCK_STATE"]).read_text())
if sys.argv[1] == "-c":
    sys.exit(0)
if sys.argv[1] == "-f":
    if os.environ.get("MOCK_FAIL") == "yes":
        sys.exit(1)
    state["live_config"] = Path(os.environ["MOCK_CONFIG"]).read_text()
    state["applications"].append("nft-apply")
    state["table"] = [{"table": {"family": "inet", "name": "cvp_filter"}},
                      {"rule": {"expr": state["live_config"]}}]
    Path(os.environ["MOCK_STATE"]).write_text(json.dumps(state))
    sys.exit(0)
assert sys.argv[1:] == ["-j", "list", "table", "inet", "cvp_filter"]
if "table" not in state:
    sys.exit(1)
print(json.dumps({"nftables": state["table"]}))
''')
        helper = self.executable("firewall-state", f'''
import runpy, sys
sys.argv += ["--config", {str(self.config)!r}, "--nft", {str(nft)!r}]
runpy.run_path({str(ROLES / "firewall/files/cvp-firewall-state")!r}, run_name="__main__")
''')
        verify = self.directory / "verify.yml"
        verify.write_text(yaml.safe_dump(self.relocate(load_tasks("firewall", "verify.yml"))))
        tasks = self.relocate(load_tasks("firewall", "activate.yml"))[1:]
        for task in tasks:
            for nested in task.get("block", []):
                if "ansible.builtin.include_tasks" in nested:
                    nested["ansible.builtin.include_tasks"] = str(verify)
        record = self.directory / "live.json"
        values = defaults("firewall") | {"firewall_state_helper": str(helper), "firewall_state_record": str(record),
                                         "firewall_activation_stamp": str(self.stamp)}
        self.play(tasks, values)
        self.play(tasks, values)
        self.assertEqual(json.loads(self.state.read_text())["applications"], ["nft-apply", "nft-apply"])
        checks = self.relocate(load_tasks("firewall", "verify.yml"))
        for drift in ("absent", "tampered", "config"):
            state = json.loads(self.state.read_text())
            if drift == "absent":
                state.pop("table")
            elif drift == "tampered":
                state["table"].append({"rule": {"expr": "accept everything"}})
            else:
                self.config.write_text("different desired config")
            self.state.write_text(json.dumps(state))
            before = self.state.read_bytes(), record.read_bytes()
            self.play(checks, values, success=False, check=True)
            self.assertEqual(before, (self.state.read_bytes(), record.read_bytes()))
            self.play(tasks, values)
            self.play(checks, values, check=True)
        self.environment["MOCK_FAIL"] = "yes"
        self.play(tasks, values, success=False)
        self.assertFalse(record.exists())
        self.environment.pop("MOCK_FAIL")
        self.play(tasks, values)


class SSHRenderingTests(LocalAnsibleTests):
    def test_real_ansible_template_and_openssh_parser_are_idempotent(self):
        sshd = os.environ.get("CVP_TEST_SSHD") or shutil.which("sshd")
        if not sshd:
            self.fail("A real OpenSSH parser is required: install sshd or set CVP_TEST_SSHD; no daemon is started")
        key = self.directory / "hostkey"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        policy = self.directory / "sshd_config.d/00-cvp-hardening.conf"
        policy.parent.mkdir()
        policy.write_text(task_named("base", "Install the SSH hardening policy", "sshd.yml")["ansible.builtin.copy"]["content"])
        main = self.directory / "sshd_config"
        original = f"# Initial configuration\nPasswordAuthentication yes\nKbdInteractiveAuthentication yes\nHostKey {key}\n"
        template = self.directory / "sshd_config.j2"
        template.write_text((ROLES / "base/templates/sshd_config.j2").read_text().replace("/etc/ssh", str(self.directory)))
        read = task_named("base", "Read the SSH main configuration", "sshd.yml")
        read["ansible.builtin.slurp"]["src"] = str(main)
        task = task_named("base", "Put the managed SSH policy before existing global settings", "sshd.yml")
        task["ansible.builtin.template"].update(src=str(template), dest=str(main), owner=getpass.getuser(),
                                             group=grp.getgrgid(os.getgid()).gr_name,
                                             validate=f"{shlex.quote(sshd)} -t -f %s")
        for initial in (original, f"Include {policy}\\n\\n" + original):
            main.write_text(initial)
            self.play([read, task], {})
            expected = f"Include {policy}\n" + original
            self.assertEqual(main.read_text(), expected)
            self.assertRegex(self.play([read, task], {}), r"changed=0\s")
            self.assertEqual(main.read_text(), expected)
            result = subprocess.run([sys.executable, str(ROLES / "base/files/cvp-validate-sshd"),
                                     "--sshd", sshd, "--config", str(main), "--user", getpass.getuser(),
                                     "--user", "root"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class WireGuardRouteTests(LocalAnsibleTests):
    def test_no_peer_mesh_still_requires_its_connected_route(self):
        module = runpy.run_path(str(ROLES / "wireguard/files/cvp-wireguard-state"))
        wanted = {"public": "local-key", "port": 51820, "mtu": 1420, "address": "192.0.2.1/24",
                  "peers": {}, "fingerprint": "applied"}
        observed = {"public": "local-key", "port": 51820, "fwmark": "off", "mtu": 1420,
                    "up": True, "addresses": [wanted["address"]], "peers": {}}
        connected = {"dst": "192.0.2.0/24", "dev": "wg0", "protocol": "kernel",
                     "scope": "link", "prefsrc": "192.0.2.1", "flags": []}
        command = ["ip", "-4", "-j", "route", "show", "table", "main", "exact", "192.0.2.0/24"]
        record = self.directory / "record.json"
        record.write_text(json.dumps({"fingerprint": "applied", "interface": "wg0", "address": wanted["address"]}))
        for routes in ([connected], []):
            for action in ("inspect", "verify", "apply"):
                with self.subTest(routes=routes, action=action):
                    calls = []

                    def run(argv):
                        calls.append(argv)
                        self.assertEqual(argv, command)
                        return SimpleNamespace(stdout=json.dumps(routes))

                    before = record.read_bytes()
                    output = io.StringIO()
                    with patch.dict(module["main"].__globals__, {"desired": lambda _: wanted,
                                                               "live": lambda _: observed, "run": run}), \
                            patch.object(sys, "argv", ["wg-state", action, "--interface", "wg0", "--config", "unused",
                                                       "--record", str(record)]), contextlib.redirect_stdout(output):
                        if routes:
                            module["main"]()
                        else:
                            with self.assertRaisesRegex(ValueError, "Missing or ambiguous"):
                                module["main"]()
                    self.assertEqual(calls, [command])
                    self.assertEqual(record.read_bytes(), before)
                    if routes and action == "apply":
                        self.assertEqual(json.loads(output.getvalue()), {"changed": False})

    def test_absent_or_down_interface_inspection_defers_routes_and_cannot_verify(self):
        module = runpy.run_path(str(ROLES / "wireguard/files/cvp-wireguard-state"))
        wanted = {"public": "local-key", "port": 51820, "mtu": 1420, "address": "192.0.2.1/24", "peers": {}}
        down = {"public": "local-key", "port": 51820, "fwmark": "off", "mtu": 1420,
                "up": False, "addresses": [wanted["address"]], "peers": {}}
        record = self.directory / "absent-record.json"

        def unexpected_run(argv):
            self.fail("Inactive inspection attempted a route lookup or mutation: " + repr(argv))

        for observed in (None, down):
            for action in ("inspect", "verify"):
                with self.subTest(observed=observed, action=action):
                    output = io.StringIO()
                    with patch.dict(module["main"].__globals__, {"desired": lambda _: wanted,
                                                               "live": lambda _: observed, "run": unexpected_run}), \
                            patch.object(sys, "argv", ["wg-state", action, "--interface", "wg0", "--config", "unused",
                                                       "--record", str(record)]), contextlib.redirect_stdout(output):
                        if action == "inspect":
                            module["main"]()
                            self.assertEqual(json.loads(output.getvalue()), {"present": observed is not None, "matches": False})
                        else:
                            with self.assertRaises(ValueError):
                                module["main"]()
                    self.assertFalse(record.exists())

    def test_route_fences_are_readonly_and_check_every_peer(self):
        module = runpy.run_path(str(ROLES / "wireguard/files/cvp-wireguard-state"))
        wanted = {"address": "192.0.2.1/24", "fingerprint": "applied",
                  "peers": {"one": {"allowed": ["192.0.2.2/32"]},
                            "two": {"allowed": ["192.0.2.3/32"]}}}
        observed = {"up": True, "addresses": [wanted["address"]]}
        record = self.directory / "record.json"
        record.write_text(json.dumps({"fingerprint": "applied", "address": wanted["address"], "interface": "wg0"}))
        connected = {"dst": "192.0.2.0/24", "dev": "wg0", "protocol": "kernel",
                     "scope": "link", "prefsrc": "192.0.2.1", "flags": []}
        command = ["ip", "-4", "-j", "route", "show", "table", "main", "exact", "192.0.2.0/24"]
        lookups = [["ip", "-4", "-j", "route", "get", peer, "from", "192.0.2.1"]
                   for peer in ("192.0.2.2", "192.0.2.3")]
        cases = [("missing", [], None), ("ambiguous", [connected, connected], None),
                 ("malformed", {}, None), ("non-object", [None], None)]
        for key, value in (("dev", "external"), ("protocol", "static"), ("scope", "global"),
                           ("prefsrc", "192.0.2.9"), ("dst", "192.0.2.0/25"),
                           ("type", "blackhole"), ("flags", ["linkdown"]), ("gateway", "192.0.2.9")):
            cases.append((key, [connected | {key: value}], None))
        for result in ([], {}, [None], [{"dev": "external"}], [{"dev": "wg0", "gateway": "192.0.2.9"}],
                       [{"dev": "wg0", "type": "local"}], [{"dev": "wg0", "multipath": [{}]}],
                       [{"dev": "wg0", "flags": ["linkdown"]}], [{"dev": "wg0"}, {"dev": "wg0"}]):
            cases.append(("peer", [connected], result))
        for name, routes, second_peer in cases:
            for action in ("inspect", "verify", "apply"):
                with self.subTest(case=name, routes=routes, peer=second_peer, action=action):
                    calls = []

                    def run(argv):
                        calls.append(argv)
                        if argv == command:
                            result = routes
                        elif argv == lookups[0]:
                            result = [{"dev": "wg0"}]
                        elif argv == lookups[1]:
                            result = second_peer
                        else:
                            self.fail("Unexpected or mutating WireGuard command: " + repr(argv))
                        return SimpleNamespace(stdout=json.dumps(result))

                    before = record.read_bytes()
                    with patch.dict(module["main"].__globals__, {"desired": lambda _: wanted,
                                                               "live": lambda _: observed, "run": run}), \
                            patch.object(sys, "argv", ["wg-state", action, "--interface", "wg0", "--config", "unused",
                                                       "--record", str(record)]):
                        with self.assertRaises(ValueError):
                            module["main"]()
                    self.assertEqual(record.read_bytes(), before)
                    self.assertEqual(calls[0], command)
                    if second_peer is not None:
                        self.assertEqual(calls, [command, *lookups])
        with patch.dict(module["verify_routes"].__globals__, {"run": lambda argv: SimpleNamespace(
                stdout=json.dumps([connected] if argv == command else [{"dev": "wg0"}]))}):
            module["verify_routes"](wanted, "wg0")

    def test_route_command_failure_and_invalid_json_fail_closed(self):
        module = runpy.run_path(str(ROLES / "wireguard/files/cvp-wireguard-state"))
        wanted = {"address": "192.0.2.1/24", "peers": {}}
        for response in ("not-json", "null", "[false]"):
            with self.subTest(response=response), patch.dict(module["verify_routes"].__globals__,
                    {"run": lambda _: SimpleNamespace(stdout=response)}):
                with self.assertRaises(ValueError):
                    module["verify_routes"](wanted, "wg0")
        def failed_run(argv):
            raise ValueError("ip failed")

        with patch.dict(module["verify_routes"].__globals__, {"run": failed_run}):
            with self.assertRaisesRegex(ValueError, "ip failed"):
                module["verify_routes"](wanted, "wg0")
