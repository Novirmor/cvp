#!/usr/bin/env python3
import copy
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:
    executable = shutil.which("ansible-playbook")
    if not executable or os.environ.get("CVP_VERIFICATION_TEST_PYTHON"):
        raise
    with Path(executable).resolve().open() as stream:
        interpreter = shlex.split(stream.readline().strip()[2:])
    if not interpreter or not Path(interpreter[0]).name.startswith("python"):
        raise RuntimeError("ansible-playbook must use its Python interpreter directly")
    os.environ["CVP_VERIFICATION_TEST_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])


ROOT = Path(__file__).resolve().parent.parent
PLAYBOOKS = ROOT / "ansible/playbooks"


def plays(name):
    return yaml.safe_load((PLAYBOOKS / name).read_text())


def tasks(value):
    for entry in value:
        if "tasks" in entry:
            yield from tasks(entry["tasks"])
        elif "block" in entry:
            yield from tasks(entry["block"])
        else:
            yield entry


def task(name, source="verify.yml"):
    return copy.deepcopy(next(row for row in tasks(plays(source)) if row.get("name") == name))


def assertion(expressions):
    return {"name": "Check fixture evidence", "ansible.builtin.assert": {"that": expressions}}


def node(name="agent", address="10.77.0.2", ready="True"):
    return {"metadata": {"name": name}, "status": {
        "conditions": [{"type": "Ready", "status": ready}],
        "addresses": [{"type": "InternalIP", "address": address}],
    }}


class VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="cvp-verification-")
        cls.work = Path(cls.temporary.name)
        cls.actions = cls.work / "action_plugins"
        cls.actions.mkdir()
        (cls.actions / "cvp_api_stub.py").write_text(
            "import json, os\nfrom ansible.plugins.action import ActionBase\n"
            "class ActionModule(ActionBase):\n"
            "    def run(self, tmp=None, task_vars=None):\n"
            "        assert self._task.delegate_to == 'server'\n"
            "        assert self._task.args == {'kubeconfig': '/etc/rancher/k3s/k3s.yaml', "
            "'api_version': 'v1', 'kind': 'Node'}\n"
            "        return dict(changed=False, resources=json.loads(os.environ['CVP_TEST_NODES']))\n"
        )
        (cls.actions / "cvp_bootstrap_stub.py").write_text(
            "import os\nfrom ansible.plugins.action import ActionBase\n"
            "class ActionModule(ActionBase):\n"
            "    def run(self, tmp=None, task_vars=None):\n"
            "        assert self._task.check_mode\n"
            "        operation = self._task.args['operation']\n"
            "        if operation == 'getent':\n"
            "            account = None if os.environ['CVP_TEST_HOME'] == 'absent-account' "
            "else ['x', '1000', '1000', '', '/fixture/ops', '/bin/bash']\n"
            "            return dict(changed=False, ansible_facts={'getent_passwd': {'ops': account}})\n"
            "        if operation == 'stat':\n"
            "            return dict(changed=False, stat={'isdir': os.environ['CVP_TEST_HOME'] == 'present'})\n"
            "        if operation == 'authorized_key':\n"
            "            assert os.environ['CVP_TEST_HOME'] == 'present'\n"
            "        assert operation in ('user', 'copy', 'authorized_key')\n"
            "        return dict(changed=True, msg='Predicted fixture ' + operation)\n"
        )
        cls.sudo = cls.work / "sudo-must-not-run"
        cls.sudo_marker = cls.work / "sudo-invoked"
        cls.sudo.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(cls.sudo_marker))}\nexit 99\n")
        cls.sudo.chmod(0o700)
        cls.bin = cls.work / "bin"
        cls.bin.mkdir()
        (cls.bin / "apt-get").symlink_to(cls.sudo)
        (cls.bin / "sudo").symlink_to(cls.sudo)
        cls.readyz = cls.work / "k3s"
        cls.readyz.write_text(
            f"#!{sys.executable}\nimport os, sys\n"
            "assert sys.argv[1:] == ['kubectl', '--kubeconfig=/etc/rancher/k3s/k3s.yaml', 'get', '--raw=/readyz']\n"
            "print(os.environ.get('CVP_TEST_READYZ', 'ok'))\n"
            "sys.exit(int(os.environ.get('CVP_TEST_API_RC', '0')))\n"
        )
        cls.readyz.chmod(0o700)
        cls.config = cls.work / "ansible.cfg"
        cls.config.write_text(
            f"[defaults]\naction_plugins={cls.actions}\nroles_path={ROOT / 'ansible/roles'}\n"
            f"local_tmp={cls.work / 'controller'}\nremote_tmp={cls.work / 'remote'}\n"
            "retry_files_enabled=False\n"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_play(self, content, *, check=True, success=True, inventory=None, limit=None, env=None):
        playbook = self.work / "fixture.yml"
        playbook.write_text(yaml.safe_dump(content, sort_keys=False))
        if inventory is None:
            inventory = {"all": {"hosts": {"fixture": {
                "ansible_connection": "local", "ansible_become": False,
                "ansible_python_interpreter": sys.executable,
            }}}}
        inventory_file = self.work / "inventory.yml"
        inventory_file.write_text(yaml.safe_dump(inventory))
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("ANSIBLE_", "CVP_"))}
        environment.update(ANSIBLE_CONFIG=str(self.config), ANSIBLE_NOCOLOR="1",
                           ANSIBLE_BECOME_EXE=str(self.sudo), PYTHONDONTWRITEBYTECODE="1",
                           PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                           XDG_CONFIG_HOME=str(self.work / "config"),
                           CVP_BOOTSTRAP_ADMIN_KEYS='["ssh-ed25519 AAAAFixture"]')
        environment.update(env or {})
        result = subprocess.run(
            ["ansible-playbook", "-i", str(inventory_file), str(playbook),
             *(["--check"] if check else []), *(["--limit", limit] if limit else [])],
            env=environment, text=True, capture_output=True, timeout=90,
        )
        self.assertFalse(self.sudo_marker.exists(), result.stdout + result.stderr)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def run_tasks(self, selected, variables=None, **kwargs):
        return self.run_play([{"name": "Exercise real Ansible verification tasks", "hosts": "all",
                               "gather_facts": False, "vars": variables or {}, "tasks": selected}], **kwargs)

    def reply(self, selected, output="", rc=0):
        selected = copy.deepcopy(selected)
        selected["ansible.builtin.command"] = {
            "argv": [sys.executable, "-c", f"import sys; print({output!r}); sys.exit({rc})"]}
        return selected

    def test_wireguard_exact_json_predicate_in_normal_and_check_mode(self):
        read = task("Read WireGuard address")
        self.assertEqual(read["ansible.builtin.command"], "ip -j address show dev {{ wireguard_interface }}")
        require = task("Verify the expected WireGuard address is configured")
        for check in (False, True):
            for address, prefix, valid in (("10.77.0.2", 24, True), ("110.77.0.2", 24, False),
                                           ("10.77.0.20", 24, False), ("10.77.0.2", 32, False)):
                output = json.dumps([{"ifname": "wg0", "addr_info": [
                    {"family": "inet", "local": address, "prefixlen": prefix}]}])
                with self.subTest(check=check, address=address, prefix=prefix):
                    self.run_tasks([self.reply(read, output), require,
                                    assertion(["not verify_wireguard_address.changed",
                                               "not verify_wireguard_address.skipped | default(false)"])],
                                   {"wireguard_address": "10.77.0.2", "wireguard_interface": "wg0"},
                                   check=check, success=valid)
        for output in ("not-json", "[]", "{}", '[{"ifname":"wg0"}]'):
            with self.subTest(output=output):
                self.run_tasks([self.reply(read, output), require],
                               {"wireguard_address": "10.77.0.2", "wireguard_interface": "wg0"}, success=False)

    def test_tailscale_requires_backend_running_and_valid_json(self):
        for check in (False, True):
            for output, rc, valid in (
                ('{"BackendState":"Running"}', 0, True),
                ('{"BackendState":"Stopped","unrelated":"Running"}', 0, False),
                ('{"unrelated":"Running"}', 0, False),
                ('{"BackendState":"Running"}', 1, False),
                ('{"BackendState":"Running"', 0, False),
                ('[]', 0, False),
            ):
                with self.subTest(check=check, output=output, rc=rc):
                    self.run_tasks([
                        self.reply(task("Check Tailscale without changing enrollment"), output, rc),
                        task("Require Tailscale to be running"),
                        assertion(["not verify_tailscale.changed", "not verify_tailscale.skipped | default(false)"]),
                    ], check=check, success=valid)

    def test_all_discovery_commands_execute_in_check_mode(self):
        selected = []
        for source in ("verify.yml", "probe.yml", "probe-wireguard.yml"):
            for index, row in enumerate(tasks(plays(source))):
                if "ansible.builtin.command" not in row:
                    continue
                with self.subTest(source=source, task=row["name"]):
                    self.assertIs(row.get("check_mode"), False)
                    self.assertIs(row.get("changed_when"), False)
                read = self.reply(row, "observed")
                for key in ("when", "loop", "loop_control", "delegate_to"):
                    read.pop(key, None)
                read["register"] = f"observed_{index}_{source.replace('-', '_').split('.')[0]}"
                selected.extend([read, assertion([
                    f"{read['register']}.stdout == 'observed'",
                    f"not {read['register']}.changed",
                    f"not {read['register']}.skipped | default(false)",
                ])])
        self.assertGreater(len(selected), 0)
        self.run_tasks(selected)

    def test_wait_for_observes_present_and_absent_paths_in_check_mode(self):
        wait = task("Wait for Flannel to publish the subnet environment")
        for present in (True, False):
            wait["ansible.builtin.wait_for"].update(
                path=str(self.config if present else self.work / "absent-subnet.env"), timeout=1)
            self.run_tasks([wait], {"k3s_role": "agent"}, success=present)

    def test_role_helpers_are_included_with_defaults(self):
        selected = []
        variables = {}
        for role, name in (("wireguard", "Verify the applied WireGuard configuration"),
                           ("firewall", "Verify the applied firewall policy")):
            include = task(name)
            self.assertEqual(include["ansible.builtin.include_role"], {"name": role, "tasks_from": "verify"})
            helper = self.work / f"{role}-helper"
            marker = self.work / f"{role}-verified"
            helper.write_text(
                f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n"
                "assert sys.argv[1] == 'verify'\n"
                "assert '--record' in sys.argv\n"
                f"Path({str(marker)!r}).write_text('verified')\n"
            )
            helper.chmod(0o700)
            variables[f"{role}_state_helper"] = str(helper)
            selected.append(include)
        plugin = self.actions / "cvp_service_stub.py"
        plugin.write_text(
            "from ansible.plugins.action import ActionBase\n"
            "class ActionModule(ActionBase):\n"
            "    def run(self, tmp=None, task_vars=None):\n"
            "        assert self._task.args == {'name': 'nftables.service'}\n"
            "        return dict(changed=False, status={'ActiveState': 'active'})\n"
        )
        roles = self.work / "roles"
        for role in ("firewall", "wireguard"):
            destination = roles / role
            (destination / "tasks").mkdir(parents=True)
            (destination / "defaults").mkdir()
            original = ROOT / "ansible/roles" / role
            (destination / "defaults/main.yml").write_bytes((original / "defaults/main.yml").read_bytes())
            verification = yaml.safe_load((original / "tasks/verify.yml").read_text())
            for row in verification:
                if "ansible.builtin.systemd_service" in row:
                    row["cvp_service_stub"] = row.pop("ansible.builtin.systemd_service")
            (destination / "tasks/verify.yml").write_text(yaml.safe_dump(verification))
        self.run_tasks(selected, variables, env={"ANSIBLE_ROLES_PATH": str(roles)})
        for role in ("firewall", "wireguard"):
            self.assertEqual((self.work / f"{role}-verified").read_text(), "verified")

    def api_inventory(self):
        return {"all": {"vars": {
            "ansible_connection": "local", "ansible_become": True,
            "ansible_python_interpreter": sys.executable,
            "k3s_server_host": "server", "k3s_bin_path": str(self.readyz),
        }, "children": {
            "wireguard": {"hosts": {"server": {"wireguard_address": "10.77.0.1", "ansible_become": False},
                                     "agent": {"wireguard_address": "10.77.0.2"}}},
            "k3s_servers": {"hosts": {"server": {}}},
            "k3s_agents": {"hosts": {"agent": {}}},
        }}}

    def test_agent_limit_still_delegates_api_and_checks_selected_nodes(self):
        play = copy.deepcopy(next(play for play in plays("verify.yml") if play.get("hosts") == "wireguard"))
        play["gather_facts"] = False
        play["tasks"] = [row for row in play["tasks"] if row.get("name") == "Verify selected nodes through the control plane"]
        self.assertEqual(len(play["tasks"]), 1)
        for row in tasks([play]):
            self.assertNotIn("ansible_become", row.get("vars", {}))
            if "kubernetes.core.k8s_info" in row:
                row["cvp_api_stub"] = row.pop("kubernetes.core.k8s_info")
        for check in (False, True):
            for resources, readyz, rc, valid in (
                ([node(), node("server", "10.77.0.1", "False"), node("extra")], "ok", 0, True),
                ([node()], "ok", 0, True),
                ([], "ok", 0, False),
                ([node("agent-other")], "ok", 0, False),
                ([node(ready="False")], "ok", 0, False),
                ([node(address="10.77.0.20")], "ok", 0, False),
                ([node()], "not ready", 0, False),
                ([node()], "ok", 1, False),
            ):
                with self.subTest(check=check, resources=resources, readyz=readyz, rc=rc):
                    content = [{"ansible.builtin.import_playbook": str(PLAYBOOKS / "load-operator-config.yml")}, play]
                    output = self.run_play(content, inventory=self.api_inventory(), limit="agent", check=check,
                                           success=valid, env={"CVP_TEST_NODES": json.dumps(resources),
                                                               "CVP_TEST_READYZ": readyz, "CVP_TEST_API_RC": str(rc)})
                    self.assertIn("agent -> server", output)
                    if valid:
                        self.assertIn("Verified selected nodes only: agent", output)

    def test_bootstrap_check_mode_defers_prerequisites_and_unknown_homes(self):
        for prerequisites, home in ((False, "absent-account"), (True, "absent-account"),
                                    (True, "absent-home"), (True, "present")):
            content = plays("bootstrap-access.yml")
            for row in tasks(content):
                if row.get("name") in ("Require a Debian-family host with apt", "Check minimal Ansible prerequisites"):
                    self.assertIs(row.get("check_mode"), False)
                    rc = int(not prerequisites and row["name"] == "Check minimal Ansible prerequisites")
                    row["ansible.builtin.raw"] = f"{shlex.quote(sys.executable)} -c 'raise SystemExit({rc})'"
                for module in ("user", "copy", "getent", "stat"):
                    key = "ansible.builtin." + module
                    if key in row:
                        row["cvp_bootstrap_stub"] = {"operation": module, "parameters": row.pop(key)}
                if "ansible.posix.authorized_key" in row:
                    row["cvp_bootstrap_stub"] = {
                        "operation": "authorized_key", "parameters": row.pop("ansible.posix.authorized_key")}
            inventory = {"all": {"children": {"wireguard": {"hosts": {"fixture": {
                "ansible_connection": "local", "ansible_become": False, "ansible_user": "root",
                "ansible_python_interpreter": sys.executable,
            }}}}}}
            with self.subTest(prerequisites=prerequisites, home=home):
                output = self.run_play(content, inventory=inventory, env={"CVP_TEST_HOME": home})
                if not prerequisites:
                    self.assertIn("Deferred in check mode: install Python", output)
                    self.assertNotIn("TASK [Create the operator account]", output)
                elif home != "present":
                    self.assertIn("Deferred in check mode: approved SSH keys", output)
                else:
                    self.assertNotIn("Deferred in check mode:", output)


if __name__ == "__main__":
    unittest.main()
