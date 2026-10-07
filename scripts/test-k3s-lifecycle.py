#!/usr/bin/env python3
"""Run real Ansible/file/SQLite/age operations against synthetic local fixtures.

Only service control, /proc, K3s and the Kubernetes API are substituted. Plays
use local connections and temporary inventories; escalation tests use a failing
fake sudo executable and never invoke real privilege escalation.
"""
import copy
import errno
import fcntl
import io
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import importlib.util

try:
    import jinja2
    import yaml
except ImportError:
    ansible = shutil.which("ansible-playbook")
    if not ansible or os.environ.get("CVP_LIFECYCLE_ANSIBLE_PYTHON"):
        raise
    interpreter = shlex.split(Path(ansible).read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_LIFECYCLE_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], interpreter + [str(Path(__file__).resolve()), *sys.argv[1:]])


ROOT = Path(__file__).resolve().parents[1]
RESTORE = ROOT / "ansible/playbooks/restore-k3s.yml"
SERVER = ROOT / "ansible/roles/k3s_server"
VERSION = "v1.35.4+k3s1"


def run(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, check=True, **kwargs)


def write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)
    return path


def database(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE records(value TEXT)")
        db.execute("INSERT INTO records VALUES (?)", (value,))


def restore_play():
    return next(play for play in yaml.safe_load(RESTORE.read_text())
                if play.get("hosts") == "k3s_servers" and play.get("name") == "Restore the K3s datastore and tokens")


def mountinfo_field(value):
    for char, escape in (("\\", r"\134"), (" ", r"\040"), ("\t", r"\011"), ("\n", r"\012")):
        value = str(value).replace(char, escape)
    return value


class Fixture:
    def __init__(self, path, datastore="sqlite", initialized=True, peers=1, inventory_escalation=False,
                 unit_file_state="disabled"):
        self.path = path
        self.data = path / "data"
        self.bin = path / "bin"
        self.bin.mkdir(parents=True)
        self.data.mkdir()
        self.mountinfo = write(path / "mountinfo", self.mount_table())
        self.inventory_escalation = inventory_escalation
        self.events = path / "events"
        self.state = path / "service-state"
        write(self.state, "inactive")
        self.enablement = write(path / "unit-file-state", unit_file_state)
        self.config = write(path / "config.yaml", yaml.safe_dump({
            "data-dir": str(self.data), "cluster-init": datastore == "etcd",
            "agent-token-file": str(path / 'agent-token'),
        }))
        self.token = self.data / "server/token"
        self.agent_token = path / "agent-token"
        self.guard = path / "cvp/k3s-restore-in-progress"
        self.guard.parent.mkdir(mode=0o700)
        self.legacy_guard = self.data / ".cvp-restore-in-progress"
        self.lock = path / 'cvp/lifecycle.lock'
        self.authorization = path / 'run/cvp/k3s-restore-start'
        self.guard_helper = path / 'libexec/cvp-k3s-start-guard'
        self.guard_dropin = path / 'systemd/k3s.service.d/50-cvp-restore-guard.conf'
        self.unit = write(path / 'systemd/k3s.service', '[Service]\nType=notify\n')
        self.stage = path / "staging"
        self.reset_observed = path / "reset-observed.json"
        self.k3s = write(self.bin / "k3s", f'''#!{sys.executable}
import io, json, pathlib, subprocess, sys, tarfile, yaml
args = sys.argv[1:]
if args == ['--version']:
    print('k3s version {VERSION} (synthetic)')
    sys.exit(0)
if args[:2] != ['server', '--cluster-reset']:
    raise SystemExit('unexpected synthetic K3s command')
with open({str(self.events)!r}, 'a') as events:
    events.write('reset ' + ' '.join(args) + '\\n')
options = dict(arg[2:].split('=', 1) for arg in args if arg.startswith('--') and '=' in arg)
config = yaml.safe_load(pathlib.Path(options['config']).read_text())
if config.get('token-file') != {str(self.token)!r}:
    raise SystemExit('reset token-file must reference the installed recovery token')
if 'server' in config:
    raise SystemExit('reset cannot use a join URL')
plain = subprocess.run(['age', '-d', '-i', {str(path / 'age.key')!r},
                        {str(path / 'recovery.tar.gz.age')!r}], capture_output=True, check=True).stdout
with tarfile.open(fileobj=io.BytesIO(plain), mode='r:gz') as archive:
    if pathlib.Path(config['token-file']).read_bytes() != archive.extractfile('server.token').read():
        raise SystemExit('reset token does not match archive')
    if pathlib.Path(options['cluster-reset-restore-path']).read_bytes() != archive.extractfile('etcd-snapshot').read():
        raise SystemExit('reset snapshot does not match archive')
if pathlib.Path({str(self.data / 'server/cred')!r}).exists():
    raise SystemExit('fixture expected bootstrap credentials to be absent before reset')
observed = pathlib.Path({str(self.reset_observed)!r})
observed.write_text(json.dumps(config))
observed.chmod(0o600)
pathlib.Path({str(self.data / 'server/db/etcd/member/wal')!r}).mkdir(parents=True, exist_ok=True)
''', 0o700)
        self.systemctl = write(self.bin / "systemctl", f'''#!{sys.executable}
import pathlib, subprocess, sys
state = pathlib.Path({str(self.state)!r})
enablement = pathlib.Path({str(self.enablement)!r})
events = pathlib.Path({str(self.events)!r})
args = sys.argv[1:]
if args[0] == 'show-environment':
    sys.exit(0)
if args[0] == 'show' and '--all' in args:
    condition = ''
    dropin = pathlib.Path({str(self.guard_dropin)!r})
    if dropin.exists():
        argv = next(line.split('=', 1)[1] for line in dropin.read_text().splitlines() if line.startswith('ExecCondition='))
        condition = '{{ path=/usr/bin/python3 ; argv[]=' + argv + ' ; ignore_errors=no ; }}'
    values = {{'LoadState': 'loaded', 'FragmentPath': {str(self.unit)!r},
               'DropInPaths': str(dropin) if dropin.exists() else '', 'Environment': '',
               'EnvironmentFiles': '', 'PassEnvironment': '', 'Type': 'notify',
               'ExecStart': '{{ path={self.k3s} ; argv[]={self.k3s} server --config {self.config} ; ignore_errors=no ; }}',
               'ExecCondition': condition}}
    for name, value in values.items():
        print(name + '=' + value)
    sys.exit(0)
with events.open('a') as out:
    out.write(' '.join(args) + '\\n')
if args[0] == 'stop':
    if 'k3s.service' in args:
        state.write_text('inactive')
elif args[0] == 'service':
    if args[1] == 'k3s.service':
        if args[3] != 'unchanged':
            enablement.write_text('enabled' if args[3] == 'true' else 'disabled')
        if args[2] in ('started', 'restarted'):
            helper = pathlib.Path({str(self.guard_helper)!r})
            if helper.exists():
                subprocess.run([sys.executable, str(helper), {str(self.guard)!r},
                                {str(self.authorization)!r}, {str(self.lock)!r},
                                {str(self.legacy_guard)!r}], check=True)
            state.write_text('active')
        elif args[2] == 'stopped':
            state.write_text('inactive')
elif args[0] == 'show':
    if args[-1] == 'k3s.service':
        print(enablement.read_text() if '--property=UnitFileState' in args else state.read_text())
    else:
        print('inactive')
elif args[0] == 'is-active':
    print(state.read_text())
    sys.exit(0 if state.read_text() == 'active' else 3)
else:
    sys.exit(20)
''', 0o700)
        if initialized:
            if datastore == "sqlite":
                database(self.data / "server/db/state.db", "original")
            else:
                write(self.data / "server/db/etcd/member/wal/original", "original-quorum")
            write(self.token, "same-token\n")
            write(self.agent_token, "original-agent\n")
            write(self.data / "server/cred/key", "original-credential")
            write(self.data / "server/tls/key", "original-tls")
        self.identity = write(path / "age.key", run(["age-keygen"]).stdout)
        self.recipient = run(["age-keygen", "-y", str(self.identity)]).stdout.strip()
        recovery_db = path / "recovery.db"
        database(recovery_db, "recovered")
        members = {
            "state.db" if datastore == "sqlite" else "etcd-snapshot":
                recovery_db.read_bytes() if datastore == "sqlite" else b"synthetic-etcd-snapshot",
            "server.token": b"same-token\n", "agent.token": b"recovered-agent\n",
            "node": b"server1\n", "k3s.version": (VERSION + "\n").encode(),
        }
        tar_path = path / "recovery.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            for name, content in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        self.archive = path / "recovery.tar.gz.age"
        run(["age", "-r", self.recipient, "-o", str(self.archive), str(tar_path)])
        self.checksum = write(path / "recovery.tar.gz.age.sha256",
                              run(["sha256sum", self.archive.name], cwd=path).stdout)
        self.sudo_calls = path / "sudo-calls"
        fake_sudo = write(self.bin / "sudo", f'''#!/bin/sh
printf '%s\\n' "$*" >> {shlex.quote(str(self.sudo_calls))}
exit 97
''', 0o700)
        inventory_vars = {}
        if inventory_escalation:
            defaults = yaml.safe_load((ROOT / "ansible/defaults/group_vars/all.yml").read_text())
            assert defaults["ansible_become"] is True
            inventory_vars = {"ansible_become": defaults["ansible_become"], "ansible_become_method": "sudo",
                              "ansible_become_exe": str(fake_sudo)}
        self.inventory = write(path / "inventory.json", json.dumps({
            "all": {"vars": inventory_vars, "children": {"k3s_servers": {"hosts": {
                f"server{i}": {"ansible_connection": "local", "k3s_server_init": i == 1}
                for i in range(1, peers + 1)
            }}}}
        }))
        self.vars = {
            "k3s_datastore": datastore, "k3s_data_dir": str(self.data),
            "k3s_bin_path": str(self.k3s), "k3s_config_path": str(self.config),
            "k3s_server_token_path": str(self.token),
            "k3s_agent_token_server_path": str(self.agent_token),
            "k3s_cluster_init_host": "server1", "k3s_server_host": "server1",
            "k3s_backup_timer_name": "cvp-k3s-backup.timer",
            "k3s_backup_service_name": "cvp-k3s-backup.service",
            "restore_staging_root": str(self.stage),
            "restore_config": str(path / "restore-config.yaml"),
            "wireguard_address": "127.0.0.1",
            "cvp_lifecycle_lock_path": str(self.lock),
            "k3s_restore_guard_path": str(self.guard),
            "cvp_backup_identity_path": str(path / 'cvp/backup-identity.json'),
            "k3s_start_guard_path": str(self.guard_helper),
            "k3s_start_guard_dropin": str(self.guard_dropin),
            "k3s_start_authorization_path": str(self.authorization),
            "k3s_checked_unit_path": str(self.unit),
            "k3s_environment_path": str(path / 'k3s-environment'),
            "k3s_systemd_unit_roots": [str(path / 'systemd')],
            "k3s_backup_script_path": str(path / 'backup-script'),
        }
        self.env = dict(os.environ,
                        ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"),
                        ANSIBLE_LOCAL_TEMP=str(path / "ansible-local"),
                        ANSIBLE_REMOTE_TEMP=str(path / "ansible-remote"),
                        ANSIBLE_NOCOLOR="1",
                        ANSIBLE_BECOME_ALLOW_SAME_USER="true",
                        PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        K3S_RESTORE_CONFIRM="true", K3S_RESTORE_CONFIRM_HOST="server1",
                        K3S_RESTORE_ARCHIVE=str(self.archive),
                        K3S_RESTORE_CHECKSUM=str(self.checksum),
                        K3S_RESTORE_AGE_IDENTITY=str(self.identity),
                        K3S_RESTORE_PEER_RECOVERY_CONFIRMED="true",
                        K3S_RESTORE_EXPECT_NAMESPACES="kube-system",
                        K3S_RESTORE_ALLOW_VERSION_MISMATCH="")

    def mount_table(self, nested=()):
        rows = ["1 0 8:1 / / rw,relatime - ext4 /dev/vda1 rw",
                "2 1 0:2 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
                f"30 1 8:2 / {mountinfo_field(self.data)} rw,relatime shared:7 - ext4 /dev/vdb1 rw",
                f"31 30 8:2 /archive {mountinfo_field(self.data / 'server/db-archive')} rw - ext4 /dev/vdb1 rw"]
        for index, target in enumerate(nested, 100):
            rows.append(f"{index} 30 8:2 /bind-source/{index} {mountinfo_field(target)} rw,relatime - ext4 /dev/vdb1 rw")
        return "\n".join(rows) + "\n"

    def restore(self, fail_before=(), namespaces=("kube-system",), fast_reset_timeout=False, check=False,
                mounts_before=None, remove_controller_become=False, include_loader=False,
                omit_reset_token_binding=False):
        play = copy.deepcopy(restore_play())
        play["become"] = False
        play["vars"].update(self.vars)
        play["vars"]["restore_mount_check_script"] = play["vars"]["restore_mount_check_script"].replace(
            "/proc/self/mountinfo", str(self.mountinfo))
        mounts_before = mounts_before or {}

        def adapt(tasks):
            result = []
            for task in tasks:
                included = task.get('ansible.builtin.include_tasks')
                if included and included.startswith('../roles/k3s_server/tasks/'):
                    task.pop('ansible.builtin.include_tasks')
                    task['block'] = yaml.safe_load((SERVER / 'tasks' / included.split('/tasks/', 1)[1]).read_text())
                elif included and (SERVER / 'tasks' / included).is_file():
                    task.pop('ansible.builtin.include_tasks')
                    task['block'] = yaml.safe_load((SERVER / 'tasks' / included).read_text())
                if task.get("name") in mounts_before:
                    mounted = mounts_before[task["name"]]
                    for target in mounted:
                        result.extend([
                            {"ansible.builtin.file": {"path": str(target), "state": "directory", "mode": "0700"},
                             "vars": {"ansible_become": False}},
                            {"ansible.builtin.copy": {"dest": str(target / "mount-sentinel"),
                                                       "content": "mounted-data", "mode": "0600"},
                             "vars": {"ansible_become": False}},
                        ])
                    result.append({"ansible.builtin.copy": {"dest": str(self.mountinfo),
                                                            "content": self.mount_table(mounted), "mode": "0600"},
                                   "vars": {"ansible_become": False}})
                if task.get("name") in fail_before:
                    result.append({"name": "Inject " + task["name"],
                                   "ansible.builtin.fail": {"msg": "synthetic fault"}})
                for section in ("block", "rescue", "always"):
                    if section in task:
                        task[section] = adapt(task[section])
                if self.inventory_escalation and task.get("delegate_to") != "localhost" and not any(
                        key in task for key in ("block", "rescue", "always")):
                    task.setdefault("vars", {})["ansible_become"] = False
                if remove_controller_become and (task.get("delegate_to") == "localhost"
                                                  or task.get("name") == "Validate the recovery unit on the controller"):
                    task.get("vars", {}).pop("ansible_become", None)
                for module in ("ansible.builtin.copy", "ansible.builtin.file"):
                    if module in task:
                        for key, value in (("owner", os.getuid()), ("group", os.getgid())):
                            if key in task[module]:
                                task[module][key] = str(value)
                if "ansible.builtin.tempfile" in task:
                    task["ansible.builtin.tempfile"]["path"] = str(self.path)
                if "ansible.builtin.systemd_service" in task:
                    args = task.pop("ansible.builtin.systemd_service")
                    enabled = str(args["enabled"]).lower() if "enabled" in args else "unchanged"
                    task["ansible.builtin.command"] = {
                        "argv": [str(self.systemctl), "service", args.get("name", "manager"), args.get("state", "unchanged"), enabled]
                    }
                    task.pop("async", None)
                    task.pop("poll", None)
                if "ansible.builtin.wait_for" in task:
                    task.pop("ansible.builtin.wait_for")
                    task["ansible.builtin.assert"] = {"that": True}
                if "kubernetes.core.k8s_info" in task:
                    task = {"name": task["name"], "ansible.builtin.set_fact": {
                        "restore_namespaces": {"resources": [{"metadata": {"name": n}} for n in namespaces]}
                    }}
                if "retries" in task:
                    task["retries"] = 1
                    task["delay"] = 0
                if fast_reset_timeout and task.get("name") == "Reset the server from the restored etcd snapshot":
                    args = task["ansible.builtin.command"]["argv"]
                    task["ansible.builtin.command"]["argv"] = [
                        "0.1s" if a == "300s" else a for a in args
                    ]
                if task.get('name') == 'Reset the server from the restored etcd snapshot':
                    args = task['ansible.builtin.command']['argv']
                    task['ansible.builtin.command']['argv'] = [
                        'PATH=' + self.env['PATH'] if a.startswith('PATH=') else a for a in args]
                if omit_reset_token_binding and task.get("name") == "Prepare the restore configuration with the archived server token":
                    task["ansible.builtin.copy"].pop("content")
                    task["ansible.builtin.copy"].update(src=str(self.config), remote_src=True)
                result.append(task)
            return result

        for section in ("pre_tasks", "tasks"):
            play[section] = adapt(play[section])
        play = absolute_lookups(play)
        plays = [play]
        if include_loader:
            imported = next(entry for entry in yaml.safe_load(RESTORE.read_text())
                            if entry.get("ansible.builtin.import_playbook") == "load-operator-config.yml")
            imported["ansible.builtin.import_playbook"] = str(ROOT / "ansible/playbooks/load-operator-config.yml")
            plays.insert(0, imported)
            inventory = json.loads(self.inventory.read_text())
            inventory["all"]["children"]["wireguard"] = {"children": {"k3s_servers": {}}}
            write(self.inventory, json.dumps(inventory))
        return subprocess.run(["ansible-playbook", "-i", str(self.inventory), "--limit", "server1", "/dev/stdin"]
                              + (["--check"] if check else []),
                              input=json.dumps(plays), env=self.env, text=True, capture_output=True)

    def rows(self):
        with sqlite3.connect(self.data / "server/db/state.db") as db:
            return db.execute("SELECT value FROM records ORDER BY value").fetchall()


def absolute_lookups(value):
    if isinstance(value, dict):
        return {key: absolute_lookups(item) for key, item in value.items()}
    if isinstance(value, list):
        return [absolute_lookups(item) for item in value]
    if isinstance(value, str):
        for prefix in ('../roles/k3s_server/files/', '../../files/', '../files/'):
            value = value.replace("'" + prefix, "'" + str(SERVER / 'files') + '/')
        value = value.replace("'../templates/", "'" + str(SERVER / 'templates') + '/')
    return value


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cvp-lifecycle-")
        self.path = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_success_and_fresh_directory(self):
        f = Fixture(self.path, initialized=False)
        result = f.restore()
        self.assert_success(result)
        self.assertEqual(f.rows(), [("recovered",)])
        self.assertEqual(f.token.read_text(), "same-token\n")
        self.assertFalse(f.guard.exists())
        self.assertFalse(list(f.stage.iterdir()))
        self.assertEqual(f.enablement.read_text(), "disabled")
        self.assertFalse(f.lock.exists())
        self.assertFalse(f.authorization.exists())

    def test_checksum_for_an_unrelated_absolute_path_never_reaches_the_host(self):
        f = Fixture(self.path)
        other = write(self.path / 'other-backup.age', 'different backup')
        write(f.checksum, run(['sha256sum', str(other)]).stdout)
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('selected archive basename', result.stdout)
        self.assertEqual(f.rows(), [('original',)])
        self.assertFalse(f.events.exists())
        self.assertFalse(f.lock.exists())

    def test_a_site_lifecycle_owner_excludes_restore_before_service_or_datastore_changes(self):
        f = Fixture(self.path)
        token = secrets.token_hex(32)
        write(f.lock / 'owner', token + '\n')
        f.lock.chmod(0o700)
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((f.lock / 'owner').read_text().strip(), token)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertFalse(f.events.exists())
        self.assertFalse(f.guard.exists())
        self.assertEqual(f.rows(), [('original',)])

    def test_effective_data_directory_dropin_fails_before_replacement(self):
        f = Fixture(self.path, datastore='etcd')
        write(Path(str(f.config) + '.d') / '90-storage.yaml', 'data-dir: /other/k3s\n')
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unaccounted K3s config', result.stdout)
        self.assertFalse(f.guard.exists())
        self.assertFalse(f.events.exists())
        self.assertEqual((f.data / 'server/db/etcd/member/wal/original').read_text(), 'original-quorum')

    def test_failed_replacement_and_rollback_inhibit_subsequent_startup(self):
        f = Fixture(self.path, unit_file_state='enabled')
        write(f.state, 'active')
        result = f.restore(fail_before={'Create recovery destination directories', 'Stop K3s before rolling back'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ROLLBACK FAILED', result.stdout)
        self.assertFalse((f.data / 'server/db').exists())
        self.assertTrue(f.token.exists() and f.agent_token.exists())
        self.assertEqual(f.enablement.read_text(), 'enabled')
        self.assertTrue(f.guard.exists() and f.lock.exists())
        self.assertFalse(f.authorization.exists())
        attempted_boot = subprocess.run([sys.executable, str(f.guard_helper), str(f.guard),
                                         str(f.authorization), str(f.lock)], text=True, capture_output=True)
        self.assertEqual(attempted_boot.returncode, 1)

    def test_failed_restore_still_inhibits_startup_when_datastore_disappears(self):
        f = Fixture(self.path, unit_file_state='enabled')
        result = f.restore(fail_before={'Create recovery destination directories', 'Stop K3s before rolling back'})
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(f.guard.exists())
        f.data.rename(self.path / 'unavailable-datastore')
        f.data.mkdir()
        attempted_boot = subprocess.run([sys.executable, str(f.guard_helper), str(f.guard),
                                         str(f.authorization), str(f.lock), str(f.legacy_guard)],
                                        text=True, capture_output=True)
        self.assertEqual(attempted_boot.returncode, 1)
        self.assertTrue(f.guard.exists())

    def test_legacy_recovery_guard_blocks_restore_before_service_changes(self):
        f = Fixture(self.path)
        write(f.legacy_guard / 'transaction', 'prior-recovery')
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(f.events.exists())
        self.assertFalse(f.guard.exists())
        self.assertEqual(f.rows(), [('original',)])

    def test_restore_upgrades_the_exact_previous_startup_condition_before_replacement(self):
        f = Fixture(self.path)
        previous = ('[Service]\nExecCondition=/usr/bin/python3 ' + str(f.guard_helper) + ' '
                    + str(f.legacy_guard) + ' ' + str(f.authorization) + ' ' + str(f.lock) + '\n')
        write(f.guard_dropin, previous, 0o644)
        result = f.restore()
        self.assert_success(result)
        self.assertNotEqual(f.guard_dropin.read_text(), previous)
        self.assertIn(str(f.guard), f.guard_dropin.read_text())
        self.assertEqual(f.rows(), [('recovered',)])
        self.assertFalse(f.guard.exists() or f.lock.exists())

    def test_preservation_failure_never_deletes_original_state(self):
        f = Fixture(self.path)
        result = f.restore(fail_before={"Back up the current tokens for rollback"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("original datastore", result.stdout)
        self.assertEqual(f.rows(), [("original",)])
        self.assertEqual(f.token.read_text(), "same-token\n")
        self.assertTrue(f.guard.exists())
        self.assertNotIn("service k3s.service", f.events.read_text())

    def test_wal_and_bootstrap_material_are_restored_after_partial_replacement(self):
        f = Fixture(self.path)
        run([sys.executable, "-c", """import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('PRAGMA journal_mode=WAL')
db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
db.execute("INSERT INTO records VALUES ('committed-wal')")
db.commit()
os._exit(0)
""", str(f.data / "server/db/state.db")])
        self.assertTrue((f.data / "server/db/state.db-wal").exists())
        result = f.restore(fail_before={"Create recovery destination directories"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("original local state was restored", result.stdout)
        self.assertEqual(f.rows(), [("committed-wal",), ("original",)])
        self.assertEqual((f.data / "server/cred/key").read_text(), "original-credential")
        self.assertEqual((f.data / "server/tls/key").read_text(), "original-tls")

    def test_no_previous_database_failure_leaves_server_stopped(self):
        f = Fixture(self.path, initialized=False)
        result = f.restore(namespaces=())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((f.data / "server/db").exists())
        self.assertFalse(f.token.exists())
        self.assertEqual(f.state.read_text(), "inactive")
        self.assertEqual(f.enablement.read_text(), "disabled")
        self.assertTrue(f.guard.exists())

    def test_failed_initialized_restore_preserves_disabled_boot_policy(self):
        f = Fixture(self.path)
        result = f.restore(namespaces=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("original local state was restored", result.stdout)
        self.assertEqual(f.rows(), [("original",)])
        self.assertEqual(f.state.read_text(), "inactive")
        self.assertEqual(f.enablement.read_text(), "disabled")
        self.assertTrue(f.guard.exists())

    def test_rollback_restarts_originally_active_server_without_enabling_it(self):
        f = Fixture(self.path)
        write(f.state, "active")
        result = f.restore(namespaces=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("original local state was restored", result.stdout)
        self.assertEqual(f.rows(), [("original",)])
        self.assertEqual(f.state.read_text(), "active")
        self.assertEqual(f.enablement.read_text(), "disabled")

    def test_service_fixture_tracks_enablement_independently_of_running_state(self):
        f = Fixture(self.path)
        run([str(f.systemctl), "service", "k3s.service", "started", "true"])
        self.assertEqual(f.state.read_text(), "active")
        self.assertEqual(f.enablement.read_text(), "enabled")
        run([str(f.systemctl), "stop", "k3s.service"])
        self.assertEqual(f.state.read_text(), "inactive")
        self.assertEqual(f.enablement.read_text(), "enabled")

    def test_failed_rollback_preserves_material_and_does_not_start(self):
        f = Fixture(self.path)
        result = f.restore(fail_before={"Restore the original datastore and bootstrap trees"}, namespaces=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ROLLBACK FAILED", result.stdout)
        self.assertEqual(f.state.read_text(), "inactive")
        self.assertTrue(list(f.stage.glob("*/previous-trees.tgz")))
        self.assertTrue(f.guard.exists())
        self.assertEqual(f.events.read_text().count("service k3s.service"), 1)

    def test_raw_etcd_rollback_preserves_quorum_and_never_restarts_it_alone(self):
        f = Fixture(self.path, datastore="etcd", peers=3)
        write(f.state, "active")
        result = f.restore(namespaces=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("KEEP all original peer", result.stdout)
        self.assertEqual((f.data / "server/db/etcd/member/wal/original").read_text(), "original-quorum")
        self.assertEqual(f.state.read_text(), "inactive")
        self.assertEqual(f.enablement.read_text(), "disabled")
        self.assertEqual(f.events.read_text().count("service k3s.service"), 1)

    def test_cross_member_installed_join_url_fails_before_host_changes(self):
        f = Fixture(self.path, datastore="etcd", peers=3)
        write(f.config, yaml.safe_dump({"server": "https://other:6443", "data-dir": str(f.data)}))
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Reconcile the installed init/join topology", result.stdout)
        self.assertFalse(f.guard.exists())
        self.assertFalse(f.events.exists())

    def test_multi_server_requires_peer_plan_confirmation(self):
        f = Fixture(self.path, datastore="etcd", peers=3)
        f.env["K3S_RESTORE_PEER_RECOVERY_CONFIRMED"] = ""
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(f.events.exists())
        self.assertFalse(f.guard.exists())

    def test_absent_original_token_is_not_confused_with_absent_database(self):
        f = Fixture(self.path)
        f.agent_token.unlink()
        result = f.restore(namespaces=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("original local state was restored", result.stdout)
        self.assertEqual(f.rows(), [("original",)])
        self.assertEqual(f.token.read_text(), "same-token\n")
        self.assertFalse(f.agent_token.exists())

    def test_failed_stop_prevents_any_rollback_deletion(self):
        f = Fixture(self.path)
        result = f.restore(fail_before={"Stop K3s before rolling back"}, namespaces=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ROLLBACK FAILED", result.stdout)
        self.assertEqual(f.rows(), [("recovered",)])
        self.assertTrue(list(f.stage.glob("*/previous-trees.tgz")))
        self.assertTrue(f.guard.exists())

    def test_reset_timeout_enters_raw_rollback(self):
        f = Fixture(self.path, datastore="etcd", peers=3)
        write(f.k3s, f'''#!/bin/sh
if [ "$1" = --version ]; then
  echo 'k3s version {VERSION} (synthetic)'
  exit 0
fi
exec sleep 2
''', 0o700)
        result = f.restore(fast_reset_timeout=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("original local state was restored", result.stdout)
        self.assertEqual((f.data / "server/db/etcd/member/wal/original").read_text(), "original-quorum")
        self.assertNotIn("service k3s.service", f.events.read_text())

    def test_unresolved_guard_prevents_a_second_transaction(self):
        f = Fixture(self.path)
        write(f.guard / "transaction", "prior-recovery")
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Acquire exclusive host lifecycle ownership", result.stdout)
        self.assertEqual((f.guard / "transaction").read_text(), "prior-recovery")
        self.assertEqual(f.rows(), [("original",)])
        self.assertFalse(f.events.exists())

    def test_successful_etcd_token_rollback_reports_peer_requirements(self):
        f = Fixture(self.path, datastore="etcd", peers=3, unit_file_state="enabled")
        write(f.token, "rotated-since-snapshot\n")
        result = f.restore()
        self.assert_success(result)
        self.assertEqual(f.token.read_text(), "same-token\n")
        self.assertEqual(f.agent_token.read_text(), "recovered-agent\n")
        self.assertIn("tokens match the restored files", result.stdout)
        self.assertFalse(f.guard.exists())
        self.assertFalse(list(f.stage.iterdir()))
        self.assertEqual(f.enablement.read_text(), "enabled")
        self.assertEqual(json.loads(f.reset_observed.read_text())["token-file"], str(f.token))

    def test_fresh_etcd_reset_binds_archive_token_without_changing_virgin_init_config(self):
        f = Fixture(self.path, datastore="etcd", initialized=False)
        initial_config = f.config.read_bytes()
        self.assertNotIn("token-file", yaml.safe_load(initial_config))
        self.assertFalse(f.token.exists())
        result = f.restore()
        self.assert_success(result)
        self.assertEqual(json.loads(f.reset_observed.read_text())["token-file"], str(f.token))
        self.assertEqual(f.config.read_bytes(), initial_config)
        self.assertEqual(f.token.read_bytes(), b"same-token\n")
        self.assertEqual(f.enablement.read_text(), "disabled")

    def test_reset_fixture_rejects_unconfigured_token_even_when_archived_file_is_installed(self):
        f = Fixture(self.path, datastore="etcd")
        result = f.restore(omit_reset_token_binding=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reset token-file must reference the installed recovery token", result.stdout)
        self.assertIn("original local state was restored", result.stdout)
        self.assertFalse(f.reset_observed.exists())
        self.assertEqual(f.token.read_bytes(), b"same-token\n")
        self.assertEqual(f.enablement.read_text(), "disabled")

    def test_reset_fixture_rejects_token_content_that_does_not_match_archive(self):
        f = Fixture(self.path, datastore="etcd", initialized=False)
        token = write(f.token, "not-the-archive-token\n")
        snapshot = write(f.data / "server/db/restore-etcd-snapshot", "synthetic-etcd-snapshot")
        config = write(self.path / "reset-config.yaml", yaml.safe_dump({"token-file": str(token)}))
        result = subprocess.run([str(f.k3s), "server", "--cluster-reset",
                                 f"--config={config}", f"--cluster-reset-restore-path={snapshot}"],
                                env=f.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reset token does not match archive", result.stderr)
        self.assertFalse(f.reset_observed.exists())

    def test_failed_controller_validation_cleans_plaintext_without_host_access(self):
        f = Fixture(self.path)
        write(f.checksum, "0" * 64 + "  " + f.archive.name + "\n")
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Recovery unit validation failed", result.stdout)
        self.assertFalse(list(self.path.glob("*cvp-k3s-restore")))
        self.assertFalse(list(self.path.glob("*cvp-k3s-transfer")))
        self.assertFalse(f.events.exists())
        self.assertFalse(f.guard.exists())

    def test_first_host_failure_has_initialized_phases_and_cleans_controller(self):
        f = Fixture(self.path)
        result = f.restore(fail_before={"Read the installed K3s version"})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("is undefined", result.stdout)
        self.assertIn("Restore preparation failed", result.stdout)
        self.assertFalse(list(self.path.glob("*cvp-k3s-restore")))
        self.assertFalse(list(self.path.glob("*cvp-k3s-transfer")))
        self.assertFalse(f.events.exists())
        self.assertFalse(f.guard.exists())

    def test_plaintext_is_removed_before_remote_access_even_if_later_cleanup_fails(self):
        f = Fixture(self.path)
        result = f.restore(fail_before={"Read the installed K3s version", "Remove controller recovery staging"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(self.path.glob("*cvp-k3s-restore")))
        remaining = list(self.path.glob("*cvp-k3s-transfer/*"))
        self.assertEqual([p.name for p in remaining], ["recovery.age"])
        self.assertTrue(remaining[0].read_bytes().startswith(b"age-encryption.org/"))
        self.assertFalse(f.events.exists())

    def test_controller_cleanup_failure_blocks_remote_mutation(self):
        f = Fixture(self.path)
        result = f.restore(fail_before={"Remove controller plaintext before any remote operation"})
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(list(self.path.glob("*cvp-k3s-restore/age.agekey")))
        self.assertFalse(f.events.exists())
        self.assertFalse(f.guard.exists())

    def test_restore_check_mode_fails_before_any_staging_or_service_action(self):
        f = Fixture(self.path)
        result = f.restore(check=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(self.path.glob("*cvp-k3s-restore")))
        self.assertFalse(list(self.path.glob("*cvp-k3s-transfer")))
        self.assertFalse(f.events.exists())
        self.assertFalse(f.guard.exists())

    def test_archive_links_are_rejected_before_remote_access(self):
        f = Fixture(self.path)
        tar_path = self.path / "link.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            for name in ("state.db", "server.token", "agent.token", "node", "k3s.version"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = str(self.path / "outside")
                archive.addfile(info)
        f.archive.unlink()
        run(["age", "-r", f.recipient, "-o", str(f.archive), str(tar_path)])
        write(f.checksum, run(["sha256sum", f.archive.name], cwd=self.path).stdout)
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Recovery unit validation failed", result.stdout)
        self.assertFalse(list(self.path.glob("*cvp-k3s-restore")))
        self.assertFalse(f.events.exists())

    def test_symlinked_etcd_root_is_rejected_without_modifying_its_target(self):
        f = Fixture(self.path, datastore="etcd")
        original = f.data / "server/db/etcd"
        target = self.path / "external-etcd"
        original.rename(target)
        original.symlink_to(target, target_is_directory=True)
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinked datastore root", result.stdout)
        self.assertEqual((target / "member/wal/original").read_text(), "original-quorum")
        self.assertTrue(original.is_symlink())
        self.assertNotIn("reset ", f.events.read_text())

    def test_mounted_recovery_subtree_is_rejected_before_recursive_deletion(self):
        f = Fixture(self.path)
        write(f.mountinfo, f.mount_table([f.data / "server/db"]))
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("automated recursive deletion is refused", result.stdout)
        self.assertEqual(f.rows(), [("original",)])
        self.assertEqual((f.data / "server/cred/key").read_text(), "original-credential")
        self.assertTrue(f.guard.exists())

    def test_nested_same_filesystem_tls_bind_preserves_its_data(self):
        f = Fixture(self.path)
        nested = f.data / "server/tls/bind data"
        sentinel = write(nested / "sentinel", "mounted-data")
        write(f.mountinfo, f.mount_table([nested]))
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(nested), result.stdout)
        self.assertIn("automated recursive deletion is refused", result.stdout)
        self.assertEqual(sentinel.read_text(), "mounted-data")
        self.assertEqual(f.rows(), [("original",)])
        self.assertFalse(list(f.stage.glob("*/previous-trees.tgz")))

    def test_new_mount_after_preservation_blocks_replacement(self):
        f = Fixture(self.path, datastore="etcd")
        nested = f.data / "server/db/etcd/member"
        result = f.restore(mounts_before={"Revalidate mounts before replacement": [nested]})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("automated recursive deletion is refused", result.stdout)
        self.assertEqual((nested / "mount-sentinel").read_text(), "mounted-data")
        self.assertEqual((nested / "wal/original").read_text(), "original-quorum")
        self.assertEqual((f.data / "server/cred/key").read_text(), "original-credential")
        self.assertTrue(list(f.stage.glob("*/previous-trees.tgz")))
        self.assertNotIn("reset ", f.events.read_text())

    def test_new_nested_mount_blocks_rollback_deletion_and_preserves_archive(self):
        f = Fixture(self.path)
        nested = f.data / "server/db/nested bind"
        result = f.restore(namespaces=(), mounts_before={"Revalidate mounts before rollback deletion": [nested]})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ROLLBACK FAILED", result.stdout)
        self.assertIn("automated recursive deletion is refused", result.stdout)
        self.assertEqual((nested / "mount-sentinel").read_text(), "mounted-data")
        self.assertEqual(f.rows(), [("recovered",)])
        self.assertEqual(f.agent_token.read_text(), "recovered-agent\n")
        self.assertEqual(f.state.read_text(), "inactive")
        self.assertTrue(list(f.stage.glob("*/previous-trees.tgz")))
        self.assertTrue(f.guard.exists())

    def test_inventory_escalation_never_reaches_controller_sudo(self):
        f = Fixture(self.path, initialized=False, inventory_escalation=True)
        f.vars.update(k3s_backup_timer_name="custom-backup.timer", k3s_backup_service_name="custom-backup.service")
        result = f.restore()
        self.assert_success(result)
        self.assertFalse(f.sudo_calls.exists())
        self.assertIn("stop custom-backup.timer custom-backup.service", f.events.read_text())
        self.assertEqual(f.rows(), [("recovered",)])
        self.assertFalse(list(self.path.glob("*cvp-k3s-restore")))
        self.assertFalse(list(self.path.glob("*cvp-k3s-transfer")))

    def test_imported_operator_settings_preserve_env_and_do_not_escalate_locally(self):
        f = Fixture(self.path, initialized=False, inventory_escalation=True)
        configuration = write(self.path / "operator.yml", json.dumps({
            "cvp_operator_hosts": {"server1": {
                "k3s_backup_timer_name": "operator-backup.timer",
                "k3s_backup_service_name": "operator-backup.service",
            }}
        }))
        f.env["CVP_OPERATOR_CONFIG_FILE"] = str(configuration)
        f.env.pop("CVP_OPERATOR_CONFIG_SHA256", None)
        result = f.restore(include_loader=True)
        self.assert_success(result)
        self.assertFalse(f.sudo_calls.exists())
        self.assertIn("stop operator-backup.timer operator-backup.service", f.events.read_text())
        self.assertEqual(f.rows(), [("recovered",)])

    def test_inventory_escalation_validation_failure_cleanup_stays_unprivileged(self):
        f = Fixture(self.path, inventory_escalation=True)
        write(f.checksum, "0" * 64 + "  " + f.archive.name + "\n")
        result = f.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Recovery unit validation failed", result.stdout)
        self.assertFalse(f.sudo_calls.exists())
        self.assertFalse(list(self.path.glob("*cvp-k3s-restore")))
        self.assertFalse(f.events.exists())

    def test_escalation_regression_fixture_detects_keyword_only_become_false(self):
        f = Fixture(self.path, inventory_escalation=True)
        result = f.restore(remove_controller_become=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(f.sudo_calls.exists(), result.stdout + result.stderr)
        self.assertFalse(f.events.exists())


class MountTableTests(unittest.TestCase):
    def test_full_table_detects_descendants_and_ignores_ancestors_and_prefix_siblings(self):
        with tempfile.TemporaryDirectory(prefix="cvp-mount-table-") as tmp:
            f = Fixture(Path(tmp))
            script = restore_play()["vars"]["restore_mount_check_script"].replace("/proc/self/mountinfo", str(f.mountinfo))
            roots = [f.data / "server/db", f.data / "server/cred", f.data / "server/tls"]
            for target, blocked in [
                (f.data, False), (f.data / "server/db-archive/child", False),
                (f.data / "server/tls-other", False), (f.data / "server/db", True),
                (f.data / "server/db/etcd/member", True), (f.data / "server/tls/subdir", True),
                (f.data / "server/cred/bind with spaces", True),
                (f.data / "server/tls/bind\twith\ncontrols\\and-slash", True),
            ]:
                with self.subTest(target=target, blocked=blocked):
                    write(f.mountinfo, f.mount_table([target]))
                    result = subprocess.run([sys.executable, "-c", script, *map(str, roots)], text=True, capture_output=True)
                    self.assertEqual(result.returncode != 0, blocked, result.stdout + result.stderr)
            for invalid in ("", "not-a-mount-table\n"):
                write(f.mountinfo, invalid)
                result = subprocess.run([sys.executable, "-c", script, *map(str, roots)], text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)

    def test_every_controller_delegate_disables_the_connection_escalation_variable(self):
        def visit(tasks, inherited):
            for task in tasks:
                variables = inherited | task.get("vars", {})
                if task.get("delegate_to") == "localhost":
                    self.assertIs(variables.get("ansible_become"), False, task.get("name"))
                for key in ("block", "rescue", "always"):
                    visit(task.get(key, []), variables)
        play = restore_play()
        for section in ("pre_tasks", "tasks"):
            visit(play[section], {})


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cvp-backup-lifecycle-")
        self.path = Path(self.temp.name)
        self.f = Fixture(self.path)
        self.backups = self.path / "backups"
        self.proc = self.path / "proc"
        write(self.proc / "sys/kernel/random/uuid", "synthetic-run-id")
        write(self.proc / "123/exe", f"#!/bin/sh\necho 'k3s version {VERSION} (serving)'\n", 0o700)
        write(self.f.systemctl, "#!/bin/sh\necho 123\n", 0o700)
        write(self.f.bin / "date", "#!/bin/sh\necho 20260101T000000Z\n", 0o700)
        self.vars = {
            "k3s_backup_dir": str(self.backups), "k3s_bin_path": str(self.f.k3s),
            "k3s_config_path": str(self.f.config), "k3s_datastore": "sqlite",
            "k3s_data_dir": str(self.f.data), "k3s_server_token_path": str(self.f.token),
            "k3s_restore_guard_path": str(self.f.guard),
            "k3s_agent_token_server_path": str(self.f.agent_token),
            "k3s_backup_age_recipient": self.f.recipient, "k3s_backup_retention_days": 14,
            "k3s_backup_upload_command": 'test -s "$BACKUP_FILE" && test -s "$BACKUP_CHECKSUM_FILE"',
            "inventory_hostname": "server1",
        }

    def tearDown(self):
        self.temp.cleanup()

    def render(self, **changes):
        env = jinja2.Environment()
        env.filters["quote"] = shlex.quote
        script = env.from_string((SERVER / "templates/k3s-backup.j2").read_text()).render(self.vars | changes)
        script = script.replace("/proc/", str(self.proc) + "/")
        return script

    def backup(self, **changes):
        script = self.render(**changes)
        path = write(self.path / "backup.sh", script, 0o700)
        return subprocess.run(["bash", str(path)], env=self.f.env, text=True, capture_output=True)

    def test_unique_paired_bundles_and_actual_runtime_version(self):
        write(self.f.k3s, "#!/bin/sh\necho 'k3s version v9.99.0+k3s1 (disk-only)'\n", 0o700)
        for node in ("server1", "server2"):
            result = self.backup(inventory_hostname=node)
            self.assertEqual(result.returncode, 0, result.stderr)
        bundles = list(self.backups.glob("k3s-*"))
        self.assertEqual(len(bundles), 2)
        for bundle in bundles:
            self.assertEqual(len(list(bundle.iterdir())), 2)
            checksum = next(bundle.glob("*.sha256"))
            run(["sha256sum", "--check", checksum.name], cwd=bundle)
            encrypted = next(bundle.glob("*.age"))
            plain = subprocess.run(["age", "-d", "-i", str(self.f.identity), str(encrypted)], capture_output=True, check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
                version = tar.extractfile("k3s.version")
                token = tar.extractfile("server.token")
                assert version is not None and token is not None
                self.assertEqual(version.read().decode().strip(), VERSION)
                self.assertEqual(token.read(), b"same-token\n")
        self.assertFalse(list(self.backups.glob(".work.*")))

    def test_token_change_rejects_snapshot_and_cleans_plaintext(self):
        sqlite = shutil.which("sqlite3")
        assert sqlite is not None
        write(self.f.bin / "sqlite3", f'#!/bin/sh\n{shlex.quote(sqlite)} "$@"\necho changed > {shlex.quote(str(self.f.token))}\n', 0o700)
        result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Server token changed", result.stderr)
        self.assertFalse(list(self.backups.glob("k3s-*")))
        self.assertFalse(list(self.backups.glob(".work.*")))

    def test_restore_guard_blocks_backup(self):
        write(self.f.guard, "unfinished-restore")
        result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Recovery is in progress", result.stderr)
        self.assertFalse(list(self.backups.glob("k3s-*")))

    def test_missing_datastore_cannot_hide_the_persistent_backup_inhibit(self):
        write(self.f.guard / 'transaction', 'unfinished-restore')
        self.f.data.rename(self.path / 'unavailable-datastore')
        self.f.data.mkdir()
        result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Recovery is in progress', result.stderr)
        self.assertFalse(list(self.backups.glob('k3s-*')))

    def test_legacy_and_dangling_recovery_guards_block_backup(self):
        for path in (self.f.guard, self.f.legacy_guard):
            path.symlink_to(self.path / 'missing-recovery')
            result = self.backup()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Recovery is in progress', result.stderr)
            self.assertFalse(list(self.backups.glob('k3s-*')))
            path.unlink()

    def test_unsafe_symlinked_and_missing_inhibit_parents_block_backup(self):
        parent = self.f.guard.parent
        parent.chmod(0o755)
        result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unsafe recovery inhibit directory', result.stderr)
        parent.chmod(0o700)
        preserved = self.path / 'preserved-inhibit-parent'
        parent.rename(preserved)
        parent.symlink_to(preserved, target_is_directory=True)
        result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unsafe recovery inhibit directory', result.stderr)
        parent.unlink()
        result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FileNotFoundError', result.stderr)
        self.assertFalse(list(self.backups.glob('k3s-*')))
        self.assertFalse(list(self.backups.glob('.work.*')))

    def test_failed_upload_keeps_complete_encrypted_pair(self):
        result = self.backup(k3s_backup_upload_command="exit 1")
        self.assertNotEqual(result.returncode, 0)
        bundle = next(self.backups.glob("k3s-*"))
        self.assertEqual(len(list(bundle.iterdir())), 2)
        run(["sha256sum", "--check", next(bundle.glob("*.sha256")).name], cwd=bundle)

    def test_process_change_rejects_snapshot(self):
        calls = self.path / "calls"
        write(self.f.systemctl, f'''#!/bin/sh
if [ -e {shlex.quote(str(calls))} ]; then
  echo 124
else
  touch {shlex.quote(str(calls))}
  echo 123
fi
''', 0o700)
        result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("K3s restarted", result.stderr)
        self.assertFalse(list(self.backups.glob("k3s-*")))
        self.assertFalse(list(self.backups.glob(".work.*")))

    def test_concurrent_backup_lock_fails_without_creating_artifacts(self):
        self.backups.mkdir()
        with (self.backups / ".backup.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Another backup is running", result.stderr)
        self.assertFalse(list(self.backups.glob("k3s-*")))

    def test_rendered_script_passes_shellcheck(self):
        result = subprocess.run(["shellcheck", "--shell=bash", "-"], input=self.render(), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_etcd_snapshot_uses_config_and_disables_compression(self):
        write(self.f.k3s, f'''#!{sys.executable}
import pathlib, sys
args = sys.argv[1:]
if args[:2] == ['etcd-snapshot', 'save']:
    assert args[args.index('--config') + 1] == {str(self.f.config)!r}
    assert '--etcd-snapshot-compress=false' in args
    folder = pathlib.Path(args[args.index('--etcd-snapshot-dir') + 1])
    (folder / 'k3s-etcd-snapshot-server1-123').write_text('raw-etcd-snapshot')
elif args[:2] != ['etcd-snapshot', 'delete']:
    sys.exit(30)
''', 0o700)
        result = self.backup(k3s_datastore="etcd")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bundle = next(self.backups.glob("k3s-*"))
        encrypted = next(bundle.glob("*.age"))
        plain = subprocess.run(["age", "-d", "-i", str(self.f.identity), str(encrypted)], capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
            snapshot = tar.extractfile("etcd-snapshot")
            assert snapshot is not None
            self.assertEqual(snapshot.read(), b"raw-etcd-snapshot")

    def test_missing_etcd_snapshot_cannot_publish_a_recovery_unit(self):
        write(self.f.k3s, "#!/bin/sh\nexit 0\n", 0o700)
        result = self.backup(k3s_datastore="etcd")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot is missing", result.stderr)
        self.assertFalse(list(self.backups.glob("k3s-*")))
        self.assertFalse(list(self.backups.glob(".work.*")))

    def test_upload_timeout_preserves_pair_and_releases_the_backup_lock(self):
        script = self.render(k3s_backup_upload_command="sleep 3").replace("900s", "0.5s")
        path = write(self.path / "timed-backup.sh", script, 0o700)
        result = subprocess.run(["bash", str(path)], env=self.f.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        bundle = next(self.backups.glob("k3s-*"))
        self.assertEqual(len(list(bundle.iterdir())), 2)
        self.assertFalse(list(self.backups.glob(".work.*")))
        with (self.backups / ".backup.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_upload_does_not_inherit_the_lock_descriptor(self):
        result = self.backup(k3s_backup_upload_command="test ! -e /dev/fd/9")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_backup_lock_and_bundle_fit_the_unit_writable_paths(self):
        backup_path = self.path / "backup space"
        uploader_path = self.path / "off host"
        env = jinja2.Environment()
        env.filters["quote"] = shlex.quote
        unit = env.from_string((SERVER / "templates/cvp-k3s-backup.service.j2").read_text()).render(
            k3s_backup_dir=str(backup_path), k3s_backup_script_path="/usr/local/sbin/k3s-backup",
            k3s_backup_writable_paths=[str(uploader_path)])
        allowed = [shlex.split(line.split("=", 1)[1]) for line in unit.splitlines() if line.startswith("ReadWritePaths=")]
        self.assertEqual(allowed, [[str(backup_path)], [str(uploader_path)]])
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("TimeoutStartSec=16min", unit)
        result = self.backup(k3s_backup_dir=str(backup_path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((backup_path / ".backup.lock").exists())
        self.assertEqual(len(list(backup_path.glob("k3s-*"))), 1)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cvp-activation-lifecycle-")
        self.path = Path(self.temp.name)
        self.f = Fixture(self.path)
        self.proc = self.path / "proc"
        self.pid = write(self.path / "pid", "100")
        self.stamp = self.path / "activated"
        self.stall = self.path / "stall"
        self.version = write(self.path / "version", VERSION)
        self.inputs = [self.f.k3s, self.f.config, self.f.agent_token]
        self.lifecycle_token = secrets.token_hex(32)
        write(self.f.guard_helper, (SERVER / 'files/cvp-k3s-start-guard.py').read_text(), 0o755)
        guard_template = jinja2.Environment().from_string((SERVER / 'templates/restore-guard.conf.j2').read_text())
        write(self.f.guard_dropin, guard_template.render(self.f.vars) + '\n', 0o644)
        write(self.proc / "100/exe", f"#!/bin/sh\necho 'k3s version {VERSION} (synthetic)'\n", 0o700)
        write(self.f.systemctl, f'''#!{sys.executable}
import pathlib, sys
args = sys.argv[1:]
if args[0] == 'show-environment':
    sys.exit(0)
if args[0] == 'show' and '--all' in args:
    dropin = pathlib.Path({str(self.f.guard_dropin)!r})
    condition = next(line.split('=', 1)[1] for line in dropin.read_text().splitlines() if line.startswith('ExecCondition='))
    values = {{'LoadState': 'loaded', 'FragmentPath': {str(self.f.unit)!r},
               'DropInPaths': str(dropin), 'Environment': '', 'EnvironmentFiles': '',
               'PassEnvironment': '', 'Type': 'notify',
               'ExecCondition': '{{ path=/usr/bin/python3 ; argv[]=' + condition + ' ; ignore_errors=no ; }}',
               'ExecStart': '{{ path={self.f.k3s} ; argv[]={self.f.k3s} server --config {self.f.config} ; ignore_errors=no ; }}'}}
    for name, value in values.items():
        print(name + '=' + value)
    sys.exit(0)
pid_file = pathlib.Path({str(self.pid)!r})
pid = pid_file.read_text()
if args[0] == 'service':
    with open({str(self.f.events)!r}, 'a') as out:
        out.write(args[-1] + '\\n')
    if args[-1] == 'restarted' and not pathlib.Path({str(self.stall)!r}).exists():
        pid = str(int(pid) + 1)
        pid_file.write_text(pid)
        exe = pathlib.Path({str(self.proc)!r}) / pid / 'exe'
        exe.parent.mkdir()
        version = pathlib.Path({str(self.version)!r}).read_text()
        exe.write_text("#!/bin/sh\\necho 'k3s version " + version + " (synthetic)'\\n")
        exe.chmod(0o700)
elif '--property=ActiveState' in args:
    print('ActiveState=active\\nMainPID=' + pid)
else:
    print(pid)
''', 0o700)

    def tearDown(self):
        self.temp.cleanup()

    def activate(self, interrupt=False, acquire=True):
        tasks = copy.deepcopy(yaml.safe_load((SERVER / "tasks/activate.yml").read_text()))
        expanded = []
        for task in tasks:
            if 'ansible.builtin.include_tasks' in task:
                children = yaml.safe_load((SERVER / 'tasks' / task['ansible.builtin.include_tasks']).read_text())
                for child in children:
                    child['vars'] = task.get('vars', {}) | child.get('vars', {})
                expanded.extend(children)
            else:
                expanded.append(task)
        tasks = expanded
        selected = []
        if acquire:
            selected.append({'ansible.builtin.include_tasks': str(SERVER / 'tasks/lifecycle/acquire.yml')})
        for task in tasks:
            if interrupt and task["name"] == "Wait for K3s activation readiness":
                selected.append({"ansible.builtin.fail": {"msg": "simulated interrupted activation"}})
            if "ansible.builtin.systemd_service" in task:
                args = task.pop("ansible.builtin.systemd_service")
                task["ansible.builtin.command"] = {"argv": [str(self.f.systemctl), "service", args["state"]]}
                task.pop("async", None)
                task.pop("poll", None)
            if "ansible.builtin.copy" in task:
                task["ansible.builtin.copy"]["owner"] = str(os.getuid())
                task["ansible.builtin.copy"]["group"] = str(os.getgid())
            if "ansible.builtin.command" in task:
                args = task["ansible.builtin.command"].get("argv", [])
                task["ansible.builtin.command"]["argv"] = [a.replace("/proc/", str(self.proc) + "/") for a in args]
            if "retries" in task:
                task["retries"] = 1
                task["delay"] = 0
            selected.append(task)
        play = [{"hosts": "k3s_servers", "connection": "local", "become": False, "gather_facts": False,
                  "vars": self.f.vars | {"k3s_activation_inputs": list(map(str, self.inputs)),
                           "cvp_lifecycle_token": self.lifecycle_token,
                           "k3s_activation_unit": "k3s.service", "k3s_version": VERSION,
                           "k3s_activation_stamp": str(self.stamp)}, "tasks": absolute_lookups(selected)}]
        return subprocess.run(["ansible-playbook", "-i", str(self.f.inventory), "/dev/stdin"],
                              input=json.dumps(play), text=True, capture_output=True, env=self.f.env)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_interrupted_activation_retries_then_becomes_idempotent(self):
        first = self.activate(interrupt=True)
        self.assertNotEqual(first.returncode, 0)
        self.assertFalse(self.stamp.exists())
        self.assert_success(self.activate())
        self.assertTrue(self.stamp.exists())
        self.assert_success(self.activate())
        self.assertEqual(self.f.events.read_text().splitlines(), ["restarted", "restarted", "started"])

    def test_activation_without_lifecycle_ownership_cannot_restart_or_stamp(self):
        result = self.activate(acquire=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.stamp.exists())
        self.assertFalse(self.f.events.exists())

    def test_guard_created_after_preflight_prevents_activation_even_with_a_matching_lease(self):
        write(self.f.lock / 'owner', self.lifecycle_token + '\n')
        self.f.lock.chmod(0o700)
        write(self.f.guard / 'transaction', 'concurrent or unfinished recovery')
        result = self.activate(acquire=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.stamp.exists())
        self.assertFalse(self.f.events.exists())

    def test_token_change_waits_for_new_process_and_failed_activation_is_not_recorded(self):
        self.assert_success(self.activate())
        old_stamp = self.stamp.read_text()
        write(self.f.agent_token, "rotated-token\n")
        write(self.stall, "do-not-complete-restart")
        stalled = self.activate()
        self.assertNotEqual(stalled.returncode, 0)
        self.assertEqual(self.stamp.read_text(), old_stamp)
        self.stall.unlink()
        self.assert_success(self.activate())
        self.assertNotEqual(self.stamp.read_text(), old_stamp)

    def test_runtime_version_drift_restarts_even_with_matching_disk_stamp(self):
        self.assert_success(self.activate())
        write(self.proc / self.pid.read_text() / "exe", "#!/bin/sh\necho 'k3s version v1.34.0+k3s1 (old-process)'\n", 0o700)
        self.assert_success(self.activate())
        self.assertEqual(self.f.events.read_text().splitlines(), ["restarted", "restarted"])

    def test_role_check_mode_skips_token_exchange_and_activation(self):
        server_tasks = yaml.safe_load((SERVER / "tasks/main.yml").read_text())
        agent_tasks = yaml.safe_load((ROOT / "ansible/roles/k3s_agent/tasks/main.yml").read_text())
        backup_tasks = yaml.safe_load((SERVER / "tasks/backup.yml").read_text())
        names = {
            "Generate a dedicated agent join token on the init server",
            "Persist the dedicated agent join token on the init server",
            "Wait for the init server to publish its tokens",
            "Read the server token from the init server", "Read the agent token from the init server",
            "Install the server token on the joining server", "Install the agent token on the joining server",
            "Activate and verify the K3s server", "Wait for the server token to exist",
            "Read the server token from the control-plane host", "Require a non-empty server token",
            "Install the agent token without exposing it in config or logs", "Activate and verify the K3s agent",
            "Reload systemd units after backup changes", "Stop the backup service only when backups are disabled",
            "Ensure the backup timer is in the requested state",
        }
        operational = [t for t in server_tasks + agent_tasks + backup_tasks if t.get("name") in names]
        self.assertEqual(len(operational), len(names))
        plays = []
        for init in (True, False):
            plays.append({"hosts": "k3s_servers", "connection": "local", "become": False,
                          "gather_facts": False, "vars": self.f.vars | {
                              "k3s_server_init": init, "k3s_agent_token_stat": {"stat": {"exists": False}},
                              "k3s_agent_token_path": str(self.f.agent_token),
                              "k3s_backup_enabled": False, "role_path": str(SERVER),
                          }, "tasks": operational})
        result = subprocess.run(["ansible-playbook", "--check", "-i", str(self.f.inventory), "/dev/stdin"],
                                input=json.dumps(plays), text=True, capture_output=True, env=self.f.env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.f.events.exists())
        self.assertFalse(self.stamp.exists())


class LifecycleOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cvp-lifecycle-ownership-')
        self.f = Fixture(Path(self.temp.name))
        self.token = secrets.token_hex(32)

    def tearDown(self):
        self.temp.cleanup()

    def play(self, action, token=None, check=False):
        play = [{'hosts': 'k3s_servers', 'connection': 'local', 'become': False, 'gather_facts': False,
                 'vars': self.f.vars | {'cvp_lifecycle_token': self.token if token is None else token},
                 'tasks': [{'ansible.builtin.include_tasks': str(SERVER / f'tasks/lifecycle/{action}.yml')}]}]
        return subprocess.run(['ansible-playbook', '-i', str(self.f.inventory), '/dev/stdin']
                              + (['--check'] if check else []), input=json.dumps(play),
                              env=self.f.env, capture_output=True, text=True)

    def test_exclusive_acquisition_assertion_release_and_token_redaction(self):
        for action in ('acquire', 'assert', 'acquire'):
            result = self.play(action)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn(self.token, result.stdout + result.stderr)
        for action in ('acquire', 'assert', 'release'):
            result = self.play(action, token='f' * 64)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((self.f.lock / 'owner').read_text().strip(), self.token)
        self.assertEqual(self.play('release').returncode, 0)
        self.assertFalse(self.f.lock.exists())
        self.assertNotEqual(self.play('assert').returncode, 0)

    def test_check_mode_never_acquires_and_refuses_an_existing_lock(self):
        self.assertEqual(self.play('acquire', check=True).returncode, 0)
        self.assertFalse(self.f.lock.exists())
        self.assertEqual(self.play('acquire').returncode, 0)
        self.assertNotEqual(self.play('acquire', check=True).returncode, 0)
        self.assertTrue(self.f.lock.exists())

    def test_partial_owner_write_failure_removes_only_the_new_lock(self):
        spec = importlib.util.spec_from_file_location('cvp_lifecycle', SERVER / 'files/cvp-lifecycle.py')
        assert spec is not None and spec.loader is not None
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with mock.patch.object(helper.os, 'fsync', side_effect=OSError('injected write failure')):
            with self.assertRaises(OSError):
                helper.execute({'action': 'acquire', 'path': str(self.f.lock),
                                'guard': str(self.f.guard), 'token': self.token})
        self.assertFalse(self.f.lock.exists())

    def test_generated_ownership_survives_across_plays_without_regeneration(self):
        plays = []
        for action in ('acquire', 'assert', 'acquire', 'release'):
            plays.append({'hosts': 'k3s_servers', 'connection': 'local', 'become': False,
                          'gather_facts': False, 'vars': self.f.vars, 'tasks': [
                              {'ansible.builtin.include_tasks': str(SERVER / f'tasks/lifecycle/{action}.yml')}]})
        result = subprocess.run(['ansible-playbook', '-i', str(self.f.inventory), '/dev/stdin'],
                                input=json.dumps(plays), env=self.f.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.f.lock.exists())

    def test_partial_fleet_acquisition_cannot_reach_host_mutations(self):
        inventory = json.loads(self.f.inventory.read_text())
        inventory['all']['children']['k3s_servers']['hosts']['server2'] = {'ansible_connection': 'local'}
        write(self.f.inventory, json.dumps(inventory))
        locks = self.f.path / 'locks'
        prior = write(locks / 'server2/owner', 'f' * 64 + '\n')
        prior.parent.chmod(0o700)
        play = [{'hosts': 'k3s_servers', 'connection': 'local', 'become': False, 'gather_facts': False,
                 'any_errors_fatal': True,
                 'vars': self.f.vars | {'cvp_lifecycle_lock_path': str(locks) + '/{{ inventory_hostname }}'},
                 'tasks': [
                     {'ansible.builtin.include_tasks': str(SERVER / 'tasks/lifecycle/acquire.yml')},
                     {'ansible.builtin.copy': {'dest': str(self.f.path) + '/mutation-{{ inventory_hostname }}',
                                               'content': 'must not run', 'mode': '0600'}},
                 ]}]
        result = subprocess.run(['ansible-playbook', '-i', str(self.f.inventory), '/dev/stdin'],
                                input=json.dumps(play), env=self.f.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((locks / 'server1/owner').exists())
        self.assertEqual(prior.read_text(), 'f' * 64 + '\n')
        self.assertFalse(list(self.f.path.glob('mutation-*')))


class StartupGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cvp-startup-guard-')
        self.path = Path(self.temp.name)
        self.guard = self.path / 'cvp/k3s-restore-in-progress'
        self.legacy_guard = self.path / 'data/.cvp-restore-in-progress'
        self.lock = self.path / 'cvp/lifecycle.lock'
        self.auth = self.path / 'run/cvp/k3s-restore-start'
        self.token = secrets.token_hex(32)
        for folder in (self.guard, self.lock):
            write(folder / 'owner', self.token + '\n')
            folder.chmod(0o700)
        self.guard.parent.chmod(0o700)
        self.helper = SERVER / 'files/cvp-k3s-start-guard.py'

    def tearDown(self):
        self.temp.cleanup()

    def check(self):
        return subprocess.run([sys.executable, str(self.helper), str(self.guard), str(self.auth),
                               str(self.lock), str(self.legacy_guard)],
                              capture_output=True, text=True)

    def authorize(self, action='authorize'):
        request = {'action': action, 'guard': str(self.guard), 'authorization': str(self.auth),
                   'legacy_guard': str(self.legacy_guard),
                   'lock': str(self.lock), 'token': self.token}
        return run([sys.executable, str(self.helper)], input=json.dumps(request))

    def test_single_use_authorization_and_boot_inhibition(self):
        self.assertEqual(self.check().returncode, 1)
        self.authorize()
        self.assertEqual(self.check().returncode, 0)
        self.assertFalse(self.auth.exists())
        self.assertEqual(self.check().returncode, 1)
        self.authorize()
        self.auth.unlink()
        self.assertEqual(self.check().returncode, 1)
        shutil.rmtree(self.guard)
        self.assertEqual(self.check().returncode, 0)

    def test_guard_inspection_errors_fail_closed(self):
        spec = importlib.util.spec_from_file_location('cvp_start_guard', self.helper)
        assert spec is not None and spec.loader is not None
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        original = Path.lstat
        for target in (self.guard, self.guard.parent, self.legacy_guard):
            for code in (errno.EIO, errno.EACCES, errno.ENOTDIR):
                def inspect(path, *args, **kwargs):
                    if path == target:
                        raise OSError(code, 'synthetic inspection failure')
                    return original(path, *args, **kwargs)
                with self.subTest(path=target, errno=code), mock.patch.object(Path, 'lstat', inspect):
                    with self.assertRaises(OSError):
                        helper.check(self.guard, self.auth, self.lock, self.legacy_guard)

    def test_absent_inhibit_parent_is_not_a_resolved_recovery(self):
        shutil.rmtree(self.guard)
        self.lock.rename(self.path / 'preserved-lock')
        self.guard.parent.rmdir()
        self.assertEqual(self.check().returncode, 1)

    def test_legacy_inhibit_and_datastore_local_inhibit_are_denied(self):
        shutil.rmtree(self.guard)
        write(self.legacy_guard / 'transaction', 'unresolved-legacy-recovery')
        for guard in (self.guard, self.legacy_guard):
            result = subprocess.run([sys.executable, str(self.helper), str(guard), str(self.auth),
                                     str(self.lock), str(self.legacy_guard)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)

    def test_stale_boot_expired_and_wrong_owner_authorizations_are_denied(self):
        for key, value in (('boot', 'previous-boot'), ('expires', 0), ('token', 'f' * 64), ('guard', [0, 0])):
            self.authorize()
            payload = json.loads(self.auth.read_text())
            payload[key] = value
            write(self.auth, json.dumps(payload))
            self.assertEqual(self.check().returncode, 1)
            self.assertFalse(self.auth.exists())
        self.authorize()
        self.authorize('revoke')
        self.assertFalse(self.auth.exists())

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd parser unavailable')
    def test_actual_systemd_parser_accepts_the_startup_condition(self):
        unit = write(self.path / 'cvp-guard-test.service',
                     '[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/true\n', 0o644)
        values = {'k3s_data_dir': str(self.legacy_guard.parent), 'k3s_restore_guard_path': str(self.guard),
                  'k3s_start_guard_path': str(self.helper),
                  'k3s_start_authorization_path': str(self.auth), 'cvp_lifecycle_lock_path': str(self.lock)}
        rendered = jinja2.Environment().from_string((SERVER / 'templates/restore-guard.conf.j2').read_text()).render(values)
        write(Path(str(unit) + '.d') / '50-cvp-restore-guard.conf', rendered + '\n', 0o644)
        result = subprocess.run(['systemd-analyze', 'verify', '--man=no', str(unit)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class RecoveryChecksumTests(unittest.TestCase):
    def test_only_one_selected_basename_digest_is_accepted(self):
        with tempfile.TemporaryDirectory(prefix='cvp-recovery-checksum-') as directory:
            archive = write(Path(directory) / 'backup.age', 'ciphertext')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            good = f'{digest}  {archive.name}\n'
            records = [(good, True), (f'{digest} *{archive.name}\n', True),
                       (good + good, False), (good + '\n', False),
                       (f'{digest}  {archive}\n', False), (f'{digest}  ../backup.age\n', False),
                       (f'{digest}  other.age\n', False), ('0' * 64 + '  backup.age\n', False)]
            for value, valid in records:
                checksum = write(Path(directory) / 'backup.sha256', value)
                result = subprocess.run([sys.executable, str(SERVER / 'files/cvp-recovery-checksum.py'),
                                         str(archive), str(checksum)], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, valid, value + result.stderr)


class EffectiveConfigurationTests(unittest.TestCase):
    def test_previous_guard_is_accepted_only_for_preflight_not_loaded_fencing(self):
        with tempfile.TemporaryDirectory(prefix='cvp-legacy-config-') as directory:
            f = Fixture(Path(directory))
            previous = ('[Service]\nExecCondition=/usr/bin/python3 ' + str(f.guard_helper) + ' '
                        + str(f.legacy_guard) + ' ' + str(f.authorization) + ' ' + str(f.lock) + '\n')
            write(f.guard_dropin, previous, 0o644)
            for require_guard, content, success in ((False, previous, True), (True, previous, False),
                                                   (False, previous + 'Environment=K3S_TOKEN=unexpected\n', False)):
                write(f.guard_dropin, content, 0o644)
                play = [{'hosts': 'k3s_servers', 'connection': 'local', 'become': False,
                         'gather_facts': False, 'vars': f.vars | {'k3s_require_loaded_guard': require_guard},
                         'tasks': [{'ansible.builtin.include_tasks': str(SERVER / 'tasks/validate-config.yml')}]}]
                result = subprocess.run(['ansible-playbook', '-i', str(f.inventory), '/dev/stdin'],
                                        input=json.dumps(play), env=f.env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                self.assertFalse(f.events.exists())

    def test_configuration_environment_and_unit_dropins_are_rejected_by_real_ansible_tasks(self):
        with tempfile.TemporaryDirectory(prefix='cvp-effective-config-') as directory:
            f = Fixture(Path(directory))
            inputs = [Path(str(f.config) + '.d') / '90-storage.yaml',
                      Path(f.vars['k3s_environment_path']),
                      f.unit.parent / 'k3s.service.d/90-other.conf',
                      f.unit.parent / 'service.d/90-default.conf']
            for path in inputs:
                write(path, 'K3S_CONFIG_FILE=/other/config\n')
                play = [{'hosts': 'k3s_servers', 'connection': 'local', 'become': False,
                         'gather_facts': False, 'vars': f.vars, 'tasks': [
                             {'ansible.builtin.include_tasks': str(SERVER / 'tasks/validate-config.yml')}]}]
                result = subprocess.run(['ansible-playbook', '-i', str(f.inventory), '/dev/stdin'],
                                        input=json.dumps(play), env=f.env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Unaccounted', result.stdout)
                self.assertFalse(f.events.exists())
                path.unlink()


class NodePortTemplateTests(unittest.TestCase):
    def test_templates_allow_only_loopback_and_the_servicelb_host_ip(self):
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        env.filters["bool"] = bool
        base = {
            "wireguard_address": "10.66.0.2", "node_name": "server2",
            "k3s_data_dir": "/var/lib/rancher/k3s", "k3s_write_kubeconfig_mode": "0600",
            "k3s_server_token_path": "/var/lib/rancher/k3s/server/token",
            "k3s_agent_token_path": "/etc/rancher/k3s/agent-token",
            "k3s_agent_token_server_path": "/etc/rancher/k3s/agent-token",
            "k3s_cluster_init_host": "server1", "k3s_server_host": "server1",
            "hostvars": {"server1": {"wireguard_address": "10.66.0.1"}},
            "k3s_datastore": "etcd", "k3s_flannel_iface": "wg0", "k3s_flannel_backend": "vxlan",
            "k3s_cluster_cidr": "10.42.0.0/16", "k3s_service_cidr": "10.43.0.0/16",
            "k3s_cluster_dns": "10.43.0.10", "k3s_cluster_domain": "cluster.local",
            "k3s_default_local_storage_path": "/var/lib/rancher/k3s/storage",
            "k3s_tls_sans": [], "k3s_node_labels": [], "k3s_disable_components": [],
        }
        for role, init in (("k3s_server", True), ("k3s_server", False), ("k3s_agent", False)):
            with self.subTest(role=role, init=init):
                template = ROOT / f"ansible/roles/{role}/templates/config.yaml.j2"
                config = yaml.safe_load(env.from_string(template.read_text()).render(base | {"k3s_server_init": init}))
                args = dict(arg.split("=", 1) for arg in config["kube-proxy-arg"])
                self.assertEqual(args["proxy-mode"], "iptables")
                self.assertEqual(args["iptables-localhost-nodeports"], "true")
                networks = [ipaddress.ip_network(cidr) for cidr in args["nodeport-addresses"].split(",")]
                self.assertEqual(config["node-ip"], base["wireguard_address"])
                for allowed in ("127.0.0.1", config["node-ip"]):
                    self.assertTrue(any(ipaddress.ip_address(allowed) in network for network in networks))
                for denied in ("198.51.100.23", "10.66.0.1", "10.42.0.1", "100.64.0.10", "2001:db8::23"):
                    self.assertFalse(any(ipaddress.ip_address(denied) in network for network in networks))
                for family in (4, 6):
                    family_networks = [n for n in networks if n.version == family]
                    self.assertTrue(family_networks, "an empty family falls back to a public wildcard upstream")
                    self.assertFalse(any(n.prefixlen == 0 for n in family_networks))

    def test_invalid_nodeport_address_inputs_fail_the_actual_ansible_gate(self):
        with tempfile.TemporaryDirectory(prefix="cvp-nodeport-") as tmp:
            fixture = Fixture(Path(tmp))
            cases = [("10.66.0.2", True), ("192.0.2.7", True)] + [
                (value, False) for value in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "10.1.2.999",
                                             "10.66.0.2/24", "10.66.0.2,0.0.0.0/0", "2001:db8::1",
                                             "10.66.0.2\n", "010.1.2.3")]
            tasks = []
            for value, accepted in cases:
                tasks.extend([
                    {"ansible.builtin.set_fact": {"nodeport_accepted": False}},
                    {"block": [
                        {"ansible.builtin.include_tasks": str(SERVER / "tasks/validate-nodeport.yml"),
                         "vars": {"wireguard_address": value}},
                        {"ansible.builtin.set_fact": {"nodeport_accepted": True}},
                    ], "rescue": [{"ansible.builtin.set_fact": {"nodeport_accepted": False}}]},
                    {"ansible.builtin.assert": {"that": "nodeport_accepted == " + str(accepted).lower()}},
                ])
            play = [{"hosts": "k3s_servers", "connection": "local", "become": False,
                     "gather_facts": False, "tasks": tasks}]
            result = subprocess.run(["ansible-playbook", "-i", str(fixture.inventory), "/dev/stdin"],
                                    input=json.dumps(play), text=True, capture_output=True, env=fixture.env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(fixture.events.exists())


if __name__ == "__main__":
    unittest.main()
