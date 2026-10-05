#!/usr/bin/env python3
import base64
import copy
import getpass
import grp
import json
import os
from pathlib import Path
import subprocess
import unittest

from test_host_network_security import LocalAnsibleTests, defaults, load_tasks, task_named
from test_host_network_reconcile import ServiceActivationTests, SSHRenderingTests, FirewallActivationTests, WireGuardRouteTests


class NetworkCheckModeTests(LocalAnsibleTests):
    def test_new_operator_check_mode_validates_keys_without_installation(self):
        self.executable("getent", "import sys\nsys.exit(2)\n")
        key = self.directory / "operator"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        target = self.directory / "authorized_keys"
        self.play(load_tasks("base", "authorized-keys.yml"), {
            "base_admin_user": "cvp-check-mode-absent",
            "base_admin_authorized_keys": [key.with_suffix(".pub").read_text().strip()],
        }, check=True, module_defaults={"ansible.posix.authorized_key": {"path": str(target)}})
        self.assertFalse(target.exists())

    def test_base_readonly_discovery_and_assertions_in_check_mode(self):
        for name, source in {"systemd-detect-virt": "print('lxc')", "grep": "", "test": "",
                             "sysctl": "print('1')", "swapon": ""}.items():
            self.executable(name, source + "\n")
        names = {
            "Require a supported Debian-family host", "Detect the virtualization environment",
            "Require a conclusive virtualization detection", "Classify the detected environment",
            "Require a declared environment to match the detected one", "Select the effective environment",
            "Read overlay filesystem registration", "Require host-provided kernel facilities on LXC guests",
            "Check cgroup delegation and TUN access in LXC", "Refuse unsupported container capabilities",
            "Check LXC sysctl values and writable guest controls", "Check LXC guest sysctl writability without changing values",
            "Require LXC provider sysctls and writable guest sysctls", "Require known uplinks for IPv6 router advertisements",
            "Check IPv6 router advertisement controls in LXC", "Require writable IPv6 router advertisement controls in LXC",
            "Read active swap devices", "Require LXC host to provide swap-free operation",
        }
        tasks = [task for task in load_tasks("base") if task["name"] in names]
        self.assertEqual(len(tasks), len(names))
        values = defaults("base") | {
            "ansible_os_family": "Debian", "ansible_service_mgr": "systemd", "node_virtualization": "auto",
            "node_container_ids": ["lxc"], "node_vm_ids": ["kvm"], "ansible_interfaces": ["eth0"],
            "base_ra_interfaces": ["eth0"], "base_module_paths": {"results": [{"stat": {"exists": True}}]},
            "base_cgroup_v2": {"stat": {"exists": True}}, "base_tun_device": {"stat": {"exists": True, "ischr": True}},
            "base_cgroup_controllers": {"content": base64.b64encode(b"cpu memory pids").decode()},
        }
        self.play(tasks + [{"name": "Check discovery results", "ansible.builtin.assert": {
            "that": ["base_env == 'lxc'", "base_virt.stdout == 'lxc'", "base_swap_devices.stdout == ''"]}}],
            values, check=True)
        self.play(tasks, values | {"node_virtualization": "vm"}, check=True, success=False)

    def test_fresh_wireguard_check_mode_never_generates_or_persists_keys(self):
        calls = Path(self.environment["MOCK_CALLS"])
        self.executable("wg", r'''
import json, os, sys
from pathlib import Path
with Path(os.environ["MOCK_CALLS"]).open("a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
if os.environ.get("MOCK_WG_AVAILABLE") == "false":
    sys.exit(127)
if sys.argv[1] == "--version":
    print("wireguard-tools")
elif sys.argv[1] == "show":
    print("")
elif sys.argv[1] == "pubkey":
    print(sys.stdin.read().strip().replace("private", "public"))
else:
    sys.exit("A mutating WireGuard command was attempted")
''')
        tasks = []
        for original in load_tasks("wireguard"):
            if original["name"] == "Render the owner-managed WireGuard mesh":
                break
            if original["name"] in ("Require WireGuard inventory data", "Require persisted public keys for every peer",
                                    "Install WireGuard tools", "Create WireGuard directories", "Install the in-place WireGuard reconciler"):
                continue
            task = copy.deepcopy(original)
            if "ansible.builtin.copy" in task:
                task["ansible.builtin.copy"]["owner"] = getpass.getuser()
                task["ansible.builtin.copy"]["group"] = grp.getgrgid(os.getgid()).gr_name
            tasks.append(task)
        key = self.directory / "privatekey"
        values = defaults("wireguard") | {"wireguard_private_key_file": str(key), "wireguard_public_key": "new-public"}
        for supplied, tools in (("", "true"), ("new-private", "true"), ("new-private", "false")):
            calls.unlink(missing_ok=True)
            self.environment["MOCK_WG_AVAILABLE"] = tools
            self.play(tasks, values | {"wireguard_private_key": supplied}, check=True)
            self.assertFalse(key.exists())
            invocations = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertNotIn(["genkey"], invocations)
            self.assertEqual(["pubkey"] in invocations, bool(supplied) and tools == "true")
        self.environment["MOCK_WG_AVAILABLE"] = "true"
        self.play(tasks, values | {"wireguard_private_key": "wrong-private"}, check=True, success=False)
        self.assertFalse(key.exists())

    def test_check_mode_reads_tailscale_without_enrolling_or_fabricating_access(self):
        self.mock_tailscale()
        values = defaults("tailscale") | defaults("firewall") | {
            "node_name": "test-node", "tailscale_auth_key": "synthetic-auth-secret",
        }
        tasks = [task_named("tailscale", name) for name in (
            "Read Tailscale backend state", "Enroll Tailscale when an external auth key is supplied",
            "Refresh the Tailscale backend state", "Select the refreshed Tailscale state",
            "Reconcile mutable Tailscale settings on an enrolled host")]
        tasks.extend(task_named("firewall", name) for name in (
            "Read Tailscale state before firewall activation",
            "Require a verified private or temporary bootstrap administration path"))
        self.play(tasks, values, check=True, success=False)
        self.play(tasks, values | {"firewall_admin_access": {"stdout": '{"path":"tailscale"}'}}, check=True)
        self.assertFalse(Path(self.environment["MOCK_CALLS"]).exists())
        Path(self.environment["MOCK_STATE"]).write_text(json.dumps({"backend": "NeedsLogin"}))
        self.play(tasks, values, check=True, success=False)
        self.play(tasks, values | {"firewall_ssh_ipv4_source_cidrs": ["192.0.2.1/32"]}, check=True, success=False)
        self.play(tasks, values | {"firewall_ssh_ipv4_source_cidrs": ["192.0.2.1/32"],
                                  "firewall_admin_access": {"stdout": '{"path":"source-cidr"}'}}, check=True)
        self.assertFalse(Path(self.environment["MOCK_CALLS"]).exists())

    def test_check_mode_never_enters_network_activation(self):
        for role, name in (("firewall", "Activate and verify the host firewall"),
                           ("wireguard", "Activate and verify the WireGuard interface")):
            task = task_named(role, name)
            task["ansible.builtin.include_tasks"] = str(self.directory / "must-not-be-opened.yml")
            self.play([task], defaults(role), check=True)


def activation_tests():
    suite = unittest.TestSuite()
    for cls in (ServiceActivationTests, SSHRenderingTests, FirewallActivationTests, WireGuardRouteTests, NetworkCheckModeTests):
        for name in cls.__dict__:
            if name.startswith("test_"):
                suite.addTest(cls(name))
    return suite


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(activation_tests())
    raise SystemExit(not result.wasSuccessful())
