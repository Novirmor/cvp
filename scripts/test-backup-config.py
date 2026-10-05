#!/usr/bin/env python3
import copy
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

try:
    import yaml
except ImportError:
    executable = shutil.which("ansible-playbook")
    if not executable or os.environ.get("CVP_BACKUP_TEST_ANSIBLE_PYTHON"):
        raise
    with Path(executable).resolve().open() as stream:
        shebang = stream.readline().strip()
    if not shebang.startswith("#!/"):
        raise RuntimeError("ansible-playbook must use an absolute Python shebang")
    interpreter = shlex.split(shebang[2:])
    if not Path(interpreter[0]).name.startswith("python"):
        raise RuntimeError("ansible-playbook must use its pinned Python interpreter directly")
    os.environ["CVP_BACKUP_TEST_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])


ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "ansible/roles/k3s_server"
TIMER = "cvp-k3s-backup.timer"
SERVICE = "cvp-k3s-backup.service"
GUARD = "Check backup continuity before any K3s changes"
MUTATION_MODULES = {
    "ansible.builtin.apt", "ansible.builtin.file", "ansible.builtin.template",
    "ansible.builtin.systemd_service", "ansible.builtin.get_url", "ansible.builtin.copy",
}


def result(output, rc=0, stderr=""):
    return {"stdout": output + "\n", "rc": rc, "stderr": stderr}


def state(enabled="enabled", active="active", service="inactive") -> dict:
    load = "not-found" if enabled == "not-found" else "loaded"
    return {
        "timer": {"LoadState": load, "UnitFileState": "" if load == "not-found" else enabled, "ActiveState": active},
        "service": {"LoadState": load, "UnitFileState": "" if load == "not-found" else "static", "ActiveState": service},
        "show_overrides": {},
    }


MISSING_UNIT_RESPONSES = {
    249: {
        "is-enabled": result("", 1, f"Failed to get unit file state for {TIMER}: No such file or directory\n"),
        "show": result("LoadState=not-found\nActiveState=inactive\nUnitFileState="),
    },
    252: {
        "is-enabled": result("", 1, f"Failed to get unit file state for {TIMER}: No such file or directory\n"),
        "show": result("LoadState=not-found\nActiveState=inactive\nUnitFileState="),
    },
    253: {
        "is-enabled": result("not-found", 4),
        "show": result("LoadState=not-found\nActiveState=inactive\nUnitFileState="),
    },
}


SYSTEMCTL = r'''import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["CVP_BACKUP_TEST_EVENTS"], "a") as stream:
    stream.write(json.dumps({"probe": args}) + "\n")
assert args[:6] == ["show", "--all", "--property=LoadState", "--property=UnitFileState", "--property=ActiveState", "--"], args
assert len(args) == 7, args
state = json.loads(pathlib.Path(os.environ["CVP_BACKUP_TEST_STATE"]).read_text())
key = {"cvp-k3s-backup.timer": "timer", "cvp-k3s-backup.service": "service"}[args[-1]]
value = state["show_overrides"].get(args[-1])
if value is None:
    value = {"rc": 0, "stderr": "", "stdout": "".join(name + "=" + content + "\n" for name, content in state[key].items())}
sys.stdout.write(value["stdout"])
sys.stderr.write(value["stderr"])
sys.exit(value["rc"])
'''

MUTATOR = r'''import json, os, pathlib, sys
name, enabled = sys.argv[1:]
with open(os.environ["CVP_BACKUP_TEST_EVENTS"], "a") as stream:
    stream.write(json.dumps({"mutation": name}) + "\n")
state_path = pathlib.Path(os.environ["CVP_BACKUP_TEST_STATE"])
state = json.loads(state_path.read_text())
if name == "K3s binary write sentinel":
    pathlib.Path(os.environ["CVP_BACKUP_TEST_BINARY"]).write_text("changed binary")
    if state.get("enable_after_binary"):
        state["timer"].update(LoadState="loaded", UnitFileState="enabled", ActiveState="active")
if name == "Install the K3s SQLite and token backup script":
    pathlib.Path(os.environ["CVP_BACKUP_TEST_SCRIPT"]).write_text("changed backup configuration")
if name == "Stop the backup service only when backups are disabled":
    state["service"].update(LoadState="loaded", UnitFileState="static", ActiveState="inactive")
if name == "Ensure the backup timer is in the requested state":
    state["timer"].update(LoadState="loaded", UnitFileState=enabled,
                          ActiveState="active" if enabled == "enabled" else "inactive")
state_path.write_text(json.dumps(state))
'''


class BackupReadOnlyInterfaceTests(unittest.TestCase):
    @unittest.skipUnless(Path("/run/systemd/system").is_dir() and os.access("/usr/bin/systemctl", os.X_OK),
                         "local systemd manager is unavailable")
    def test_real_manager_reports_missing_unit_without_error(self):
        tasks = yaml.safe_load((SERVER / "tasks/backup.yml").read_text())
        argv = next(task["ansible.builtin.command"]["argv"] for task in tasks if "ansible.builtin.command" in task)
        self.assertEqual(argv, ["timeout", "--kill-after=5s", "15s", "systemctl", "show", "--all",
                                "--property=LoadState", "--property=UnitFileState", "--property=ActiveState",
                                "--", "{{ item }}"])
        env = {key: value for key, value in os.environ.items() if not key.startswith(("SYSTEMD_", "DBUS_"))}
        name = "cvp-backup-config-test-" + uuid.uuid4().hex + ".timer"
        query = subprocess.run(["/usr/bin/systemctl", *argv[4:-1], name],
                               env=env, text=True, capture_output=True, timeout=15)
        self.assertEqual(query.returncode, 0, query.stderr)
        self.assertEqual(query.stderr.strip(), "")
        self.assertEqual(len(query.stdout.splitlines()), 3)
        self.assertEqual(dict(line.split("=", 1) for line in query.stdout.splitlines()), {
            "LoadState": "not-found", "UnitFileState": "", "ActiveState": "inactive",
        })


class BackupConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cvp-backup-config-")
        self.work = Path(self.temporary.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.systemctl = self.bin / "systemctl"
        self.systemctl.write_text(f"#!{sys.executable}\n" + SYSTEMCTL)
        self.systemctl.chmod(0o700)
        self.mutator = self.work / "mutator.py"
        self.mutator.write_text(MUTATOR)
        self.events = self.work / "events"
        self.state_file = self.work / "state.json"
        self.binary = self.work / "k3s"
        self.binary.write_text("original binary")
        self.backup_script = self.work / "backup-script"
        self.backup_script.write_text("persistent backup configuration")
        self.identity = self.work / 'backup-identity.json'
        self.identity.write_text(json.dumps({'timer': TIMER, 'service': SERVICE, 'script': str(self.backup_script)}))
        self.identity.chmod(0o600)
        self.lifecycle_token = secrets.token_hex(32)
        self.backup_tasks = yaml.safe_load((SERVER / "tasks/backup.yml").read_text())
        self.server_tasks = yaml.safe_load((SERVER / "tasks/main.yml").read_text())
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("ANSIBLE_", "CVP_", "K3S_"))
        }
        self.env.update({
            "ANSIBLE_CONFIG": str(self.work / "ansible.cfg"),
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "ANSIBLE_NOCOLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "CVP_BACKUP_TEST_EVENTS": str(self.events), "CVP_BACKUP_TEST_STATE": str(self.state_file),
            "CVP_BACKUP_TEST_BINARY": str(self.binary), "CVP_BACKUP_TEST_SCRIPT": str(self.backup_script),
        })
        (self.work / "ansible.cfg").write_text(
            f"[defaults]\nlocal_tmp={self.work / 'controller'}\nremote_tmp={self.work / 'remote'}\n"
        )

    def tearDown(self):
        self.temporary.cleanup()

    def mutation(self, name):
        return {
            "name": name,
            "ansible.builtin.command": {"argv": [sys.executable, str(self.mutator), name,
                                                   "{{ 'enabled' if k3s_backup_enabled | bool else 'disabled' }}"]},
            "changed_when": True,
        }

    def prepare_tasks(self):
        adapted = []
        for original in self.backup_tasks:
            task = copy.deepcopy(original)
            modules = set(task).intersection(MUTATION_MODULES)
            if modules:
                self.assertEqual(len(modules), 1)
                task.pop(modules.pop())
                task.update({key: value for key, value in self.mutation(task["name"]).items() if key != "name"})
                task.pop("async", None)
                task.pop("poll", None)
            elif "ansible.builtin.command" in task:
                argv = task["ansible.builtin.command"]["argv"]
                self.assertEqual(argv[:4], ["timeout", "--kill-after=5s", "15s", "systemctl"])
                self.assertEqual(argv[4:], ["show", "--all", "--property=LoadState", "--property=UnitFileState",
                                           "--property=ActiveState", "--", "{{ item }}"])
            elif 'ansible.builtin.include_tasks' in task:
                task['ansible.builtin.include_tasks'] = str(SERVER / 'tasks' / task['ansible.builtin.include_tasks'])
            else:
                self.assertIn("ansible.builtin.assert", task, "Unmocked backup task")
            adapted.append(task)
        (self.work / "backup.yml").write_text(yaml.safe_dump(adapted))
        first_mutation = next(index for index, task in enumerate(self.server_tasks) if set(task).intersection(MUTATION_MODULES))
        guard_index = next(index for index, task in enumerate(self.server_tasks) if task.get("name") == GUARD)
        self.assertLess(guard_index, first_mutation)
        self.assertEqual(self.server_tasks[guard_index]["ansible.builtin.include_tasks"], "backup.yml")
        self.assertIs(self.server_tasks[guard_index]["vars"]["_k3s_backup_preflight_only"], True)
        prefix = copy.deepcopy(self.server_tasks[:first_mutation])
        for index, task in enumerate(prefix):
            if task.get("ansible.builtin.include_tasks") == "validate-nodeport.yml":
                prefix[index] = {"name": task["name"], "ansible.builtin.assert": {"that": True}}
            elif "ansible.builtin.stat" in task:
                task["ansible.builtin.stat"]["path"] = str(self.work / "no-restore-guard")
            elif task.get('ansible.builtin.include_tasks') == 'validate-config.yml':
                prefix[index] = {'name': task['name'], 'ansible.builtin.assert': {'that': True}}
            elif task.get('ansible.builtin.include_tasks') == 'lifecycle/assert.yml':
                task['ansible.builtin.include_tasks'] = str(SERVER / 'tasks/lifecycle/assert.yml')
            elif "ansible.builtin.include_tasks" in task:
                self.assertEqual(task["ansible.builtin.include_tasks"], "backup.yml")
            else:
                self.assertIn("ansible.builtin.assert", task, "Unmocked server preflight task")
        return prefix

    def run_case(self, current, *, desired=False, confirm=None, success=False, check=False,
                 backup_only=False, continue_backup=False, variables=None):
        self.state_file.write_text(json.dumps(current))
        self.events.unlink(missing_ok=True)
        prefix = self.prepare_tasks()
        if backup_only:
            tasks = [{"name": "Configure backup independently", "ansible.builtin.include_tasks": "backup.yml"}]
        else:
            tasks = prefix + [self.mutation("K3s binary write sentinel")]
            if continue_backup:
                tasks.append({"name": "Configure backup after K3s", "ansible.builtin.include_tasks": "backup.yml"})
        inputs = {
            "ansible_connection": "local", "ansible_become": False, "ansible_python_interpreter": sys.executable,
            "k3s_role": "server", "k3s_version": "fixture", "wireguard_address": "192.0.2.1",
            "k3s_server_init": True, "k3s_datastore": "etcd", "k3s_data_dir": str(self.work / "data"),
            "k3s_backup_enabled": desired, "k3s_backup_timer_name": TIMER, "k3s_backup_service_name": SERVICE,
            "k3s_backup_age_recipient": "age1fixture", "k3s_backup_upload_command": "fixture-upload",
            "k3s_backup_retention_days": 14,
            "cvp_lifecycle_token": self.lifecycle_token,
            "cvp_lifecycle_lock_path": str(self.work / 'cvp/lifecycle.lock'),
            "k3s_restore_guard_path": str(self.work / 'cvp/k3s-restore-in-progress'),
            "cvp_backup_identity_path": str(self.identity),
            "k3s_backup_script_path": str(self.backup_script),
            "k3s_systemd_unit_roots": [str(self.work / 'systemd')],
        }
        if confirm is not None:
            inputs["k3s_backup_disable_confirm"] = confirm
        inputs.update(variables or {})
        play = [{"name": "Synthetic backup continuity", "hosts": "server1", "gather_facts": False,
                  "vars": inputs, "tasks": [
                      {'ansible.builtin.include_tasks': str(SERVER / 'tasks/lifecycle/acquire.yml')}, *tasks]}]
        playbook = self.work / "play.yml"
        playbook.write_text(yaml.safe_dump(play))
        completed = subprocess.run(
            ["ansible-playbook", "-i", "server1,", str(playbook), *(["--check"] if check else [])],
            env=self.env, text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(completed.returncode == 0, success, completed.stdout + completed.stderr)
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def assert_no_mutations(self, events):
        self.assertFalse(any("mutation" in event for event in events), events)
        self.assertEqual(self.binary.read_text(), "original binary")
        self.assertEqual(self.backup_script.read_text(), "persistent backup configuration")

    def test_omitted_backup_configuration_blocks_before_server_changes(self):
        for current in (state("enabled"), state("enabled", "inactive"), state("enabled-runtime")):
            with self.subTest(current=current):
                events = self.run_case(current)
                self.assert_no_mutations(events)
                self.assertEqual(len(events), 2)

    def test_confirmation_is_exact_and_host_scoped(self):
        for confirm in ("", True, "server2", "server1 "):
            with self.subTest(confirm=confirm):
                self.assert_no_mutations(self.run_case(state(), confirm=confirm))

    def test_correct_confirmation_is_readonly_early_then_allows_late_disable(self):
        events = self.run_case(state(), confirm="server1", success=True, continue_backup=True)
        mutations = [event["mutation"] for event in events if "mutation" in event]
        self.assertEqual(mutations[0], "K3s binary write sentinel")
        self.assertEqual(next(index for index, event in enumerate(events) if "mutation" in event), 2)
        self.assertIn("Stop the backup service only when backups are disabled", mutations)
        self.assertEqual(mutations[-1], "Ensure the backup timer is in the requested state")
        self.assertEqual(json.loads(self.state_file.read_text())["timer"]["UnitFileState"], "disabled")

    def test_known_new_and_already_disabled_servers_can_converge(self):
        for enabled in ("not-found", "disabled"):
            with self.subTest(enabled=enabled):
                events = self.run_case(state(enabled, "inactive"), success=True)
                self.assertEqual([event["mutation"] for event in events if "mutation" in event], ["K3s binary write sentinel"])

    def test_systemd_249_252_253_missing_units_use_successful_manager_query(self):
        for version, responses in MISSING_UNIT_RESPONSES.items():
            with self.subTest(systemd=version):
                legacy = responses["is-enabled"]
                self.assertNotEqual(legacy["rc"], 0)
                if version < 253:
                    self.assertTrue(legacy["stderr"])
                    self.assertEqual(legacy["stdout"].strip(), "")
                current = state("not-found", "inactive")
                current["show_overrides"] = {TIMER: responses["show"], SERVICE: responses["show"]}
                events = self.run_case(current, success=True)
                self.assertEqual([event["probe"][0] for event in events if "probe" in event], ["show", "show"])
                self.assertEqual([event["mutation"] for event in events if "mutation" in event], ["K3s binary write sentinel"])

    def test_desired_enabled_keeps_the_backup_service_running(self):
        for activity in ("active", "activating"):
            current = state()
            current["service"]["ActiveState"] = activity
            events = self.run_case(current, desired=True, success=True, continue_backup=True)
            mutations = [event["mutation"] for event in events if "mutation" in event]
            self.assertNotIn("Stop the backup service only when backups are disabled", mutations)
            observed = json.loads(self.state_file.read_text())
            self.assertEqual(observed["timer"]["UnitFileState"], "enabled")
            self.assertEqual(observed["service"]["ActiveState"], activity)

    def test_enabled_intent_without_credentials_fails_before_binary_changes(self):
        events = self.run_case(state(), desired=True, variables={"k3s_backup_age_recipient": ""})
        self.assert_no_mutations(events)

    def test_disabled_but_active_timer_or_service_requires_confirmation(self):
        oneshot = state("disabled", "inactive")
        oneshot["service"]["ActiveState"] = "activating"
        for current in (state("disabled", "active"), state("disabled", "inactive", "active"),
                        state("not-found", "active"), oneshot):
            with self.subTest(current=current):
                self.assert_no_mutations(self.run_case(current))

    def test_failed_or_incomplete_show_cannot_be_overridden_by_confirmation(self):
        missing = MISSING_UNIT_RESPONSES[252]["show"]["stdout"].rstrip("\n")
        for probe in (
            result("", 1), result(missing, 1), result(missing, 4), result(missing, 0, "D-Bus error"),
            result("", 124), result("", 127), result("LoadState=not-found"),
            result("LoadState=not-found\nActiveState=inactive"),
            result("LoadState=not-found\nLoadState=not-found\nActiveState=inactive"),
            result("LoadState=not-found\nUnitFileState=enabled\nActiveState=inactive"),
        ):
            current = state()
            current["show_overrides"][TIMER] = probe
            with self.subTest(probe=probe):
                self.assert_no_mutations(self.run_case(current, confirm="server1"))

    def test_ambiguous_activity_cannot_be_overridden_by_confirmation(self):
        for field, value in (("ActiveState", "unknown"), ("ActiveState", ""),
                             ("LoadState", "error"), ("LoadState", "masked"),
                             ("UnitFileState", "indirect"), ("UnitFileState", "static"),
                             ("UnitFileState", "")):
            current = state()
            current["timer"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_no_mutations(self.run_case(current, confirm="server1"))

    def test_check_mode_still_reads_and_protects_current_backup_configuration(self):
        self.assert_no_mutations(self.run_case(state(), check=True))
        events = self.run_case(state(), check=True, confirm="server1", success=True, continue_backup=True)
        self.assert_no_mutations(events)
        self.assertEqual(len(events), 4)

    def test_backup_file_alone_is_guarded_and_late_changes_are_rechecked(self):
        self.assert_no_mutations(self.run_case(state(), backup_only=True))
        current = state("disabled", "inactive")
        current["enable_after_binary"] = True
        events = self.run_case(current, continue_backup=True)
        self.assertEqual([event["mutation"] for event in events if "mutation" in event], ["K3s binary write sentinel"])
        self.assertEqual(self.backup_script.read_text(), "persistent backup configuration")

    def test_unsafe_unit_names_are_rejected_before_probing(self):
        for value in ("--now.timer", "other*.timer", "/etc/systemd/system/backup.timer", "backup.service"):
            with self.subTest(value=value):
                self.assert_no_mutations(self.run_case(state(), variables={"k3s_backup_timer_name": value}))

    def test_applied_custom_names_cannot_be_lost_or_renamed_even_with_disable_confirmation(self):
        self.identity.write_text(json.dumps({'timer': 'prior-backup.timer', 'service': 'prior-backup.service',
                                             'script': str(self.backup_script)}))
        for desired in (False, True):
            events = self.run_case(state('not-found', 'inactive'), desired=desired, confirm='server1')
            self.assert_no_mutations(events)
            self.assertEqual(events, [])
        self.assertEqual(json.loads(self.identity.read_text())['timer'], 'prior-backup.timer')

    def test_legacy_custom_units_are_discovered_without_a_ledger(self):
        self.identity.unlink()
        units = self.work / 'systemd'
        units.mkdir()
        (units / 'prior-backup.service').write_text(
            '[Unit]\nDescription=Encrypted off-host K3s datastore and token backup\n'
            '[Service]\nExecStart=' + str(self.backup_script) + '\n')
        (units / 'prior-backup.timer').write_text(
            '[Unit]\nDescription=Run encrypted off-host K3s backup\n[Timer]\nUnit=prior-backup.service\n')
        events = self.run_case(state('not-found', 'inactive'), confirm='server1')
        self.assert_no_mutations(events)
        self.assertFalse(self.identity.exists())

    def test_unknown_existing_script_without_a_ledger_fails_closed(self):
        self.identity.unlink()
        self.assert_no_mutations(self.run_case(state('not-found', 'inactive')))

    def test_fresh_install_records_identity_before_script_mutation(self):
        self.identity.unlink()
        self.backup_script.unlink()
        events = self.run_case(state('not-found', 'inactive'), success=True, continue_backup=True)
        self.assertIn('Install the K3s SQLite and token backup script', [e.get('mutation') for e in events])
        self.assertEqual(json.loads(self.identity.read_text()), {
            'timer': TIMER, 'service': SERVICE, 'script': str(self.backup_script),
        })
        self.assertEqual(self.identity.stat().st_mode & 0o777, 0o600)

    def test_check_mode_cannot_record_identity_even_with_a_record_request(self):
        self.identity.unlink()
        self.backup_script.unlink()
        events = self.run_case(state('not-found', 'inactive'), success=True, check=True, continue_backup=True,
                               variables={'_k3s_backup_identity_action': 'record'})
        self.assertFalse(any('mutation' in event for event in events))
        self.assertFalse(self.identity.exists())
        self.assertFalse(self.backup_script.exists())


if __name__ == "__main__":
    unittest.main()
