#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "scripts/cvp_wrapper_common.py"
LOADER = ROOT / "ansible/playbooks/load-operator-config.yml"


class OperatorConfigTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="cvp-operator-")
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.config = self.directory / "operator.yml"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CVP_", "ANSIBLE_"))}
        self.env.update({"ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
                         "XDG_CONFIG_HOME": str(self.directory / "config"),
                         "ANSIBLE_NOCOLOR": "1"})

    def write_config(self, data):
        self.config.write_text(json.dumps(data))
        self.env["CVP_OPERATOR_CONFIG_FILE"] = str(self.config)

    def load(self, expected, *, check=False, success=True):
        inventory = self.directory / "inventory.json"
        sudo = self.directory / "sudo-must-not-run"
        sudo.write_text("#!/bin/sh\nexit 99\n")
        sudo.chmod(0o700)
        inventory.write_text(json.dumps({"all": {"vars": {"ansible_become": True, "ansible_become_exe": str(sudo)},
            "children": {"wireguard": {"hosts": {
            "alpha": {"ansible_connection": "local"},
            "beta": {"ansible_connection": "local"},
        }}}}}))
        assertions = []
        for host, values in expected.items():
            for name, value in values.items():
                assertions.append(f"hostvars[{host!r}][{name!r}] == {value!r}")
        playbook = self.directory / "playbook.json"
        playbook.write_text(json.dumps([
            {"import_playbook": str(LOADER)},
            {"name": "Assert isolated loaded settings", "hosts": "wireguard",
             "gather_facts": False, "become": False,
             "tasks": [{"ansible.builtin.assert": {"that": assertions}}]},
        ]))
        result = subprocess.run(
            ["ansible-playbook", "-i", str(inventory), str(playbook), *(["--check"] if check else [])],
            env=self.env, text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_host_values_override_defaults_without_cross_host_leakage(self):
        self.write_config({"cvp_operator_defaults": {"k3s_backup_enabled": True},
                           "cvp_operator_hosts": {"alpha": {"storage_device": "/dev/example", "k3s_backup_enabled": False}}})
        self.load({"alpha": {"storage_device": "/dev/example", "k3s_backup_enabled": False},
                   "beta": {"k3s_backup_enabled": True, "cvp_operator_config_loaded": True}})

    def test_default_path_and_check_mode(self):
        self.write_config({"cvp_operator_defaults": {"k3s_backup_enabled": True}})
        default = Path(self.env["XDG_CONFIG_HOME"]) / "cvp/operator.yml"
        default.parent.mkdir(parents=True)
        self.config.rename(default)
        self.env.pop("CVP_OPERATOR_CONFIG_FILE")
        self.load({"alpha": {"k3s_backup_enabled": True}, "beta": {"k3s_backup_enabled": True}}, check=True)

    def test_missing_explicit_file_fails(self):
        self.env["CVP_OPERATOR_CONFIG_FILE"] = str(self.config)
        self.load({}, success=False)

    def test_unknown_host_fails(self):
        self.write_config({"cvp_operator_hosts": {"unknown": {"storage_device": "/dev/example"}}})
        self.load({}, success=False)

    def test_connection_override_fails(self):
        self.write_config({"cvp_operator_hosts": {"alpha": {"ansible_host": "different-host"}}})
        self.load({}, success=False)

    def test_changed_pinned_file_fails(self):
        self.write_config({"cvp_operator_defaults": {"k3s_backup_enabled": True}})
        self.env["CVP_OPERATOR_CONFIG_SHA256"] = hashlib.sha256(self.config.read_bytes()).hexdigest()
        self.config.write_text("{}")
        self.load({}, success=False)

    def test_no_configuration_is_optional_for_initial_inventory(self):
        self.load({"alpha": {"cvp_operator_config_loaded": True}})

    def test_whitelisted_environment_credentials_are_resolved_as_literal_data(self):
        self.env["FIXTURE_AUTH"] = "synthetic-auth-key"
        self.env["FIXTURE_WG"] = "synthetic-wireguard-key"
        self.write_config({"cvp_operator_hosts": {"alpha": {
            "tailscale_auth_key": {"env": "FIXTURE_AUTH"},
            "wireguard_private_key": {"env": "FIXTURE_WG"},
        }}})
        result = self.load({"alpha": {"tailscale_auth_key": "synthetic-auth-key", "wireguard_private_key": "synthetic-wireguard-key"}})
        self.assertNotIn("synthetic-auth-key", result.stdout + result.stderr)
        self.assertNotIn("synthetic-wireguard-key", result.stdout + result.stderr)

    def test_invalid_references_and_templates_fail_without_disclosing_values(self):
        self.env["FIXTURE_AUTH"] = "synthetic-auth-key"
        for values in (
            {"tailscale_auth_key": "{{ lookup('env', 'FIXTURE_AUTH') }}"},
            {"tailscale_auth_key": {"env": "MISSING_FIXTURE_AUTH"}},
            {"tailscale_auth_key": {"env": "FIXTURE_AUTH", "extra": True}},
            {"tailscale_auth_key": {"env": "INVALID NAME"}},
            {"tailscale_auth_key": False},
            {"storage_device": {"env": "FIXTURE_AUTH"}},
            {"base_admin_authorized_keys": ["{% synthetic-auth-key %}"]},
        ):
            with self.subTest(values=values):
                self.write_config({"cvp_operator_hosts": {"alpha": values}})
                result = self.load({}, success=False)
                self.assertNotIn("synthetic-auth-key", result.stdout + result.stderr)

    def test_pinned_absence_rejects_a_new_default_file(self):
        self.env["CVP_OPERATOR_CONFIG_ABSENT"] = "1"
        self.load({"alpha": {"cvp_operator_config_loaded": True}})
        default = Path(self.env["XDG_CONFIG_HOME"]) / "cvp/operator.yml"
        default.parent.mkdir(parents=True)
        default.write_text("{}")
        self.load({}, success=False)

    def test_dangerous_defaults_are_rejected(self):
        for key, value in (("storage_format_confirmation", "alpha"),
                           ("wireguard_rotate_private_key", True),
                           ("k3s_backup_disable_confirm", "alpha")):
            with self.subTest(key=key):
                self.write_config({"cvp_operator_defaults": {key: value}})
                self.load({}, success=False)

    def test_yaml_fallback_keeps_stdin(self):
        self.write_config({"cvp_operator_hosts": {"alpha": {"storage_device": "/dev/example"}}})
        result = subprocess.run(["python3", "-S", "-B", str(HELPER), "operator-load"],
                                input='["alpha", "beta"]', env=self.env,
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["cvp_operator_hosts"]["alpha"]["storage_device"], "/dev/example")

    def test_label_suite_never_escalates_on_the_controller(self):
        sudo = self.directory / "sudo-must-not-run"
        marker = self.directory / "sudo-was-invoked"
        sudo.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
        sudo.chmod(0o700)
        env = dict(self.env, ANSIBLE_BECOME_EXE=str(sudo))
        result = subprocess.run(
            ["ansible-playbook", "-i", str(ROOT / "ansible/inventory/hosts.yml"),
             str(ROOT / "ansible/playbooks/test-labels.yml")],
            env=env, text=True, capture_output=True, timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists(), "label tests invoked controller sudo")


if __name__ == "__main__":
    unittest.main()
