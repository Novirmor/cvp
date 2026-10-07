#!/usr/bin/env python3
import base64
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

try:
    import jsonpatch
    import yaml
except ImportError:
    executable = shutil.which("ansible-playbook")
    if not executable or os.environ.get("CVP_SITE_TEST_ANSIBLE_PYTHON"):
        raise
    interpreter = shlex.split(Path(executable).read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_SITE_TEST_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "ansible/playbooks"
ROLES = ROOT / "ansible/roles"
SITE = yaml.safe_load((PLAYBOOKS / "site.yml").read_text())
RECONCILE = "Reconcile K3s node labels and taints through the Kubernetes API"
CONTROLLER_TAINTS = [{"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule"},
                      {"key": "controller.io/protected", "effect": "NoExecute"}]
INGRESS_LABELS = ["cvp.novirmor.io/ingress=true", "svccontroller.k3s.cattle.io/enablelb=true",
                  "svccontroller.k3s.cattle.io/lbpool=public"]


def play_named(name):
    return copy.deepcopy(next(play for play in SITE if play.get("name") == name))


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


SUPPORT = '''import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).parent


def settings():
    return json.loads((ROOT / 'settings.json').read_text())


def lock(host):
    return ROOT / 'hosts' / host / 'lifecycle.lock'


def events():
    path = ROOT / 'events.jsonl'
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def record(phase, host, token=''):
    row = json.dumps(dict(phase=phase, host=host, token=token)) + '\\n'
    descriptor = os.open(ROOT / 'events.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, row.encode())
    finally:
        os.close(descriptor)


def ownership():
    owners = {row['host']: row['token'] for row in events() if row['phase'] == 'acquire'}
    for host in settings()['selected']:
        assert lock(host).is_dir(), 'mutation before all host locks: ' + host
        assert lock(host).joinpath('owner').read_text().strip() == owners[host], 'lost owner: ' + host


def lifecycle(action, host, token):
    return subprocess.run([sys.executable, str(ROOT / 'ansible/roles/k3s_server/files/cvp-lifecycle.py')],
                          input=json.dumps(dict(action=action, path=str(lock(host)), token=token,
                                                guard=str(ROOT / 'hosts' / host / 'data/.cvp-restore-in-progress'))),
                          text=True, capture_output=True)


def observe(phase, host, token=''):
    if phase == 'acquire':
        assert lock(host).joinpath('owner').read_text().strip() == token
    elif phase == 'release':
        assert not lock(host).exists()
        patched = {row['host'] for row in events() if row['phase'] == 'patch'}
        assert patched == set(settings()['selected']), 'released before reconciliation finished'
    else:
        ownership()
        if token:
            assert lock(host).joinpath('owner').read_text().strip() == token
    record(phase, host, token)
    if phase == 'base':
        before = lock(host).joinpath('owner').read_bytes()
        result = lifecycle('acquire', host, secrets.token_hex(32))
        assert result.returncode != 0 and 'another invocation' in result.stderr
        assert lock(host).joinpath('owner').read_bytes() == before
        record('restore-blocked', host)
    if settings().get('fail') == [phase, host]:
        raise RuntimeError('injected site failure: ' + phase + ':' + host)


if __name__ == '__main__':
    observe(*sys.argv[1:])
'''


API_INFO = '''from ansible.module_utils.basic import AnsibleModule

module = AnsibleModule(argument_spec=dict(kubeconfig=dict(), api_version=dict(), kind=dict(), name=dict()),
                       supports_check_mode=True)
name = module.params['name']
observe('read' if name else 'preflight-nodes', name or 'alpha')
nodes = [json.loads(path.read_text()) for path in sorted((ROOT / 'nodes').glob('*.json'))]
module.exit_json(changed=False, resources=[node for node in nodes if not name or node['metadata']['name'] == name])
'''


API_PATCH = '''import jsonpatch
from ansible.module_utils.basic import AnsibleModule

module = AnsibleModule(argument_spec=dict(kubeconfig=dict(), api_version=dict(), kind=dict(), name=dict(),
                                         patch=dict(type='list', elements='dict')), supports_check_mode=True)
name = module.params['name']
observe('patch-attempt', name)
assert not module.check_mode, 'patch module invoked in check mode'
path = ROOT / 'nodes' / (name + '.json')
node = json.loads(path.read_text())
updated = jsonpatch.apply_patch(node, module.params['patch'])
path.write_text(json.dumps(updated))
record('patch', name)
module.exit_json(changed=True, result=updated)
'''


class SiteFixture:
    def __init__(self, root, servers=2):
        self.root = root
        self.playbooks = root / "ansible/playbooks"
        self.roles = root / "ansible/roles"
        self.hosts = ["alpha", "beta", "gamma"] if servers == 2 else ["alpha", "beta", "delta", "gamma"]
        self.selected = list(self.hosts)
        self.fail: list[str] | None = None
        self.vars = yaml.safe_load((ROOT / "ansible/defaults/group_vars/all.yml").read_text())
        self.vars.update(ansible_connection="local", ansible_become=False,
                         ansible_python_interpreter=sys.executable)
        self.hostvars = {}
        for index, host in enumerate(self.hosts, 1):
            self.hostvars[host] = {
                "node_name": host, "k3s_role": "agent" if host == "gamma" else "server",
                "k3s_server_init": host == "alpha", "k3s_cluster_init_host": "alpha",
                "k3s_server_host": "alpha", "wireguard_peers_group": "wireguard",
                "wireguard_address": f"10.77.0.{index}",
                "wireguard_public_key": base64.b64encode(bytes([index]) * 32).decode(),
                "k3s_node_labels": ["cvp.novirmor.io/compute=true"] + (INGRESS_LABELS if host == "alpha" else []),
                "k3s_node_taints": ["dedicated=batch:NoSchedule"],
                "cvp_lifecycle_lock_path": str(self.lock(host)),
                "k3s_data_dir": str(root / "hosts" / host / "data"),
                "k3s_bin_path": str(root / "k3s"),
            }
            labels = {"cvp.novirmor.io/bootstrap-quarantine": "true", "cvp.novirmor.io/obsolete": "true", "kubernetes.io/os": "linux"}
            if host != "gamma":
                labels["node-role.kubernetes.io/control-plane"] = "true"
            self.set_node(host, {
                "metadata": {"name": host, "resourceVersion": "1", "labels": labels,
                             "annotations": {"controller.io/state": "keep"}},
                "spec": {"taints": [CONTROLLER_TAINTS[0],
                                    {"key": "cvp.novirmor.io/bootstrap", "value": "true", "effect": "NoSchedule"},
                                    CONTROLLER_TAINTS[1]]},
                "status": {"addresses": [{"type": "InternalIP", "address": f"10.77.0.{index}"}],
                           "conditions": [{"type": "Ready", "status": "True"}]},
            })
        self.groups = {"wireguard": self.hosts, "k3s_servers": [host for host in self.hosts if host != "gamma"],
                       "k3s_agents": ["gamma"], "ingress": ["alpha"]}
        for name in ("load-operator-config.yml", "tasks/validate-topology.yml",
                     "tasks/validate-node-tags.yml", "tasks/onboard-preflight.yml"):
            write(self.playbooks / name, (PLAYBOOKS / name).read_text())
        for name in ("cvp-topology.py", "cvp_wrapper_common.py"):
            write(root / "scripts" / name, (ROOT / "scripts" / name).read_text())
        write(root / "site_fixture.py", SUPPORT)
        k3s = write(root / "k3s", f"#!{sys.executable}\nfrom site_fixture import observe\n"
                    "observe('preflight-readyz', 'alpha')\nprint('ok')\n")
        k3s.chmod(0o700)
        for role in ("base", "tailscale", "wireguard", "firewall", "storage", "ingress_v6", "k3s_server", "k3s_agent"):
            write(self.roles / role / "tasks/main.yml", yaml.safe_dump([self.marker(role)]))
        write(self.roles / "k3s_server/files/cvp-lifecycle.py",
              (ROLES / "k3s_server/files/cvp-lifecycle.py").read_text())
        for action in ("acquire", "assert", "release"):
            tasks = yaml.safe_load((ROLES / f"k3s_server/tasks/lifecycle/{action}.yml").read_text())
            if action != "assert":
                tasks.append(self.marker(action))
            write(self.roles / f"k3s_server/tasks/lifecycle/{action}.yml", yaml.safe_dump(tasks))
        modules = root / "collections/ansible_collections/kubernetes/core/plugins/modules"
        prefix = f"import sys\nsys.path.insert(0, {str(root)!r})\nfrom site_fixture import ROOT, json, observe, record\n"
        write(modules / "k8s_info.py", prefix + API_INFO)
        write(modules / "k8s_json_patch.py", prefix + API_PATCH)
        config = write(root / "ansible.cfg", "[defaults]\nretry_files_enabled = False\n"
                       f"roles_path = {self.roles}\ncollections_path = {root / 'collections'}\n"
                       "interpreter_python = auto_silent\n[privilege_escalation]\nbecome = False\n")
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("ANSIBLE_", "CVP_"))}
        self.env.update(ANSIBLE_CONFIG=str(config), ANSIBLE_NOCOLOR="1", PYTHONDONTWRITEBYTECODE="1",
                        ANSIBLE_LOCAL_TEMP=str(root / "ansible-local"),
                        ANSIBLE_REMOTE_TEMP=str(root / "ansible-remote"),
                        XDG_CONFIG_HOME=str(root / "config"))

    def marker(self, phase):
        return {"name": "Observe isolated " + phase,
                "ansible.builtin.command": {"argv": [sys.executable, str(self.root / "site_fixture.py"), phase,
                                                      "{{ inventory_hostname }}", "{{ cvp_lifecycle_token | default('') }}"]}}

    def lock(self, host):
        return self.root / "hosts" / host / "lifecycle.lock"

    def node(self, host):
        return json.loads((self.root / "nodes" / f"{host}.json").read_text())

    def set_node(self, host, node):
        write(self.root / "nodes" / f"{host}.json", json.dumps(node))

    def events(self):
        path = self.root / "events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def run(self, *, check=False, extra=None, plays=None):
        write(self.root / "settings.json", json.dumps({"selected": self.selected, "fail": self.fail}))
        inventory = write(self.root / "inventory.json", json.dumps({"all": {"vars": self.vars, "children": {
            group: {"hosts": {host: self.hostvars[host] for host in members}}
            for group, members in self.groups.items()}}}))
        isolated = copy.deepcopy(SITE if plays is None else plays)
        for play in isolated:
            if "hosts" in play:
                play["gather_facts"] = False
        playbook = write(self.playbooks / "site.yml", yaml.safe_dump(isolated, sort_keys=False))
        return subprocess.run(["ansible-playbook", "-i", str(inventory), str(playbook),
                               "--limit", ",".join(self.selected), "-e", json.dumps(extra or {}),
                               *(["--check"] if check else [])],
                              env=self.env, text=True, capture_output=True, timeout=180)

    def lifecycle(self, action, host, token):
        return subprocess.run([sys.executable, str(self.roles / "k3s_server/files/cvp-lifecycle.py")],
                              input=json.dumps({"action": action, "path": str(self.lock(host)), "token": token,
                                                "guard": str(self.root / "hosts" / host / "data/.cvp-restore-in-progress")}),
                              text=True, capture_output=True, timeout=10)


class SiteOrchestrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cvp-site-")
        self.addCleanup(temporary.cleanup)
        self.f = SiteFixture(Path(temporary.name))

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def failure(self, result, expected):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout + result.stderr)

    def assert_owned_locks(self):
        owners = {row["host"]: row["token"] for row in self.f.events() if row["phase"] == "acquire"}
        self.assertEqual(set(owners), set(self.f.selected))
        for host, token in owners.items():
            self.assertRegex(token, r"^[0-9a-f]{64}$")
            self.assertEqual((self.f.lock(host) / "owner").read_text().strip(), token)
            self.success(self.f.lifecycle("assert", host, token))
        self.assertNotIn("release", [row["phase"] for row in self.f.events()])

    def test_all_site_plays_abort_globally_on_error(self):
        for play in SITE:
            if "hosts" in play:
                with self.subTest(play=play["name"]):
                    self.assertIs(play.get("any_errors_fatal"), True)

    def test_success_locks_before_roles_atomic_patches_before_release_and_restore_sequence(self):
        self.success(self.f.run())
        rows = self.f.events()
        self.assertEqual({row["host"] for row in rows[:3] if row["phase"] == "acquire"}, set(self.f.hosts))
        expected_roles = [(role, host) for host in self.f.hosts
                          for role in ("base", "tailscale", "wireguard", "firewall", "storage")]
        expected_roles += [("ingress_v6", "alpha"), ("k3s_server", "alpha"),
                           ("k3s_server", "beta"), ("k3s_agent", "gamma")]
        role_names = {role for role, _ in expected_roles}
        self.assertEqual([(row["phase"], row["host"]) for row in rows if row["phase"] in role_names], expected_roles)
        self.assertEqual({row["host"] for row in rows if row["phase"] == "restore-blocked"}, set(self.f.hosts))
        self.assertEqual({row["host"] for row in rows[-3:] if row["phase"] == "release"}, set(self.f.hosts))
        for host in self.f.hosts:
            node = self.f.node(host)
            self.assertEqual(node["spec"]["taints"], CONTROLLER_TAINTS + [
                {"key": "dedicated", "value": "batch", "effect": "NoSchedule"}])
            expected_labels = {"kubernetes.io/os": "linux", "cvp.novirmor.io/compute": "true",
                               "cvp.novirmor.io/role": "agent" if host == "gamma" else "control-plane"}
            if host != "gamma":
                expected_labels["node-role.kubernetes.io/control-plane"] = "true"
            if host == "alpha":
                expected_labels.update({"cvp.novirmor.io/ingress": "true", "svccontroller.k3s.cattle.io/enablelb": "true",
                                        "svccontroller.k3s.cattle.io/lbpool": "public"})
            self.assertEqual(node["metadata"]["labels"], expected_labels)
            self.assertEqual(json.loads(node["metadata"]["annotations"]["cvp.novirmor.io/managed-taints"]),
                             [{"key": "dedicated", "value": "batch", "effect": "NoSchedule"}])
            self.assertEqual(node["metadata"]["annotations"]["controller.io/state"], "keep")
            self.assertFalse(self.f.lock(host).exists())
            token = secrets.token_hex(32)
            self.success(self.f.lifecycle("acquire", host, token))
            self.success(self.f.lifecycle("release", host, token))

    def test_first_host_failure_stops_second_host_and_all_later_plays_without_release(self):
        self.f.fail = ["base", "alpha"]
        self.failure(self.f.run(), "injected site failure: base:alpha")
        self.assert_owned_locks()
        self.assertEqual([(row["phase"], row["host"]) for row in self.f.events() if row["phase"] != "acquire"],
                         [("base", "alpha"), ("restore-blocked", "alpha")])
        for host in self.f.hosts:
            self.assertIn("cvp.novirmor.io/bootstrap-quarantine", self.f.node(host)["metadata"]["labels"])
            result = self.f.lifecycle("acquire", host, secrets.token_hex(32))
            self.failure(result, "another invocation")

    def test_invalid_unselected_global_topology_fails_before_locks_and_markers(self):
        self.f.selected = ["alpha", "gamma"]
        self.f.hostvars["beta"]["wireguard_address"] = "10.77.0.1"
        self.failure(self.f.run(), "unique")
        self.assertEqual(self.f.events(), [])
        self.assertFalse(any(self.f.lock(host).exists() for host in self.f.hosts))

    def test_selection_missing_init_fails_before_locks_and_markers(self):
        self.f.selected = ["gamma"]
        self.failure(self.f.run(), "Include both alpha and alpha in --limit")
        self.assertEqual(self.f.events(), [])
        self.assertFalse(any(self.f.lock(host).exists() for host in self.f.hosts))

    def test_ingress_conflicts_fail_before_locks_and_host_roles(self):
        self.f.selected = ["alpha", "gamma"]
        for name, labels in (("alpha", []), ("beta", list(INGRESS_LABELS))):
            with self.subTest(name=name):
                previous = self.f.hostvars[name]["k3s_node_labels"]
                self.f.hostvars[name]["k3s_node_labels"] = labels
                self.failure(self.f.run(extra={"cvp_onboard_node": "gamma"}),
                             "ingress node must declare" if name == "alpha" else "non-ingress nodes must omit")
                self.assertEqual(self.f.events(), [])
                self.assertFalse(any(self.f.lock(host).exists() for host in self.f.hosts))
                self.f.hostvars[name]["k3s_node_labels"] = previous

    def test_distinct_init_and_api_servers_must_both_be_selected_and_locked(self):
        self.f = SiteFixture(self.f.root / "distinct-servers", servers=3)
        for values in self.f.hostvars.values():
            values["k3s_server_host"] = "beta"
        self.f.selected = ["alpha", "gamma"]
        before = {host: self.f.node(host) for host in self.f.hosts}
        self.failure(self.f.run(), "Include both alpha and beta in --limit")
        self.assertEqual(self.f.events(), [])
        self.assertFalse(any(self.f.lock(host).exists() for host in self.f.hosts))
        self.assertEqual({host: self.f.node(host) for host in self.f.hosts}, before)
        self.f.selected = ["alpha", "beta", "gamma"]
        self.success(self.f.run())
        rows = self.f.events()
        self.assertEqual({row["host"] for row in rows[:3] if row["phase"] == "acquire"},
                         set(self.f.selected))
        self.assertEqual({row["host"] for row in rows if row["phase"] == "base"}, set(self.f.selected))
        self.assertEqual({row["host"] for row in rows if row["phase"] == "patch"}, set(self.f.selected))
        self.assertEqual({row["host"] for row in rows[-3:] if row["phase"] == "release"},
                         set(self.f.selected))
        self.assertEqual(self.f.node("delta"), before["delta"])
        self.assertFalse(any(self.f.lock(host).exists() for host in self.f.hosts))

    def test_invalid_selected_tags_fail_before_locks_and_markers(self):
        self.f.hostvars["gamma"]["k3s_node_labels"] = ["unmanaged.example/compute=true"]
        self.failure(self.f.run(), "invalid node_name, label, or taint declaration")
        self.assertEqual(self.f.events(), [])
        self.assertFalse(any(self.f.lock(host).exists() for host in self.f.hosts))

    def test_onboard_preflight_runs_under_all_locks_before_roles(self):
        self.success(self.f.run(extra={"cvp_onboard_node": "gamma"}))
        phases = [row["phase"] for row in self.f.events()]
        self.assertEqual(phases[:5], ["acquire"] * 3 + ["preflight-readyz", "preflight-nodes"])
        self.assertGreater(phases.index("base"), phases.index("preflight-nodes"))

    def test_failed_onboard_preflight_leaves_locks_and_prevents_host_roles(self):
        node = self.f.node("beta")
        node["status"]["conditions"][0]["status"] = "False"
        self.f.set_node("beta", node)
        self.failure(self.f.run(extra={"cvp_onboard_node": "gamma"}), "Ready")
        self.assert_owned_locks()
        self.assertEqual([row["phase"] for row in self.f.events()],
                         ["acquire"] * 3 + ["preflight-readyz", "preflight-nodes"])

    def test_failed_final_patch_retains_all_locks_and_quarantine_on_unpatched_nodes(self):
        self.f.fail = ["patch-attempt", "alpha"]
        self.failure(self.f.run(), "injected site failure: patch-attempt:alpha")
        self.assert_owned_locks()
        self.assertIn("cvp.novirmor.io/bootstrap-quarantine", self.f.node("alpha")["metadata"]["labels"])

    def test_check_mode_skipped_registration_results_do_not_acquire_or_mutate(self):
        before = {host: self.f.node(host) for host in self.f.hosts}
        for selected in (self.f.hosts, ["gamma"]):
            with self.subTest(selected=selected):
                self.f.selected = selected
                result = self.f.run(check=True)
                self.success(result)
                self.assertIn("Compute patches for selected inventory nodes", result.stdout)
                self.assertEqual(self.f.events(), [])
                self.assertFalse(any(self.f.lock(host).exists() for host in self.f.hosts))
                self.assertEqual({host: self.f.node(host) for host in self.f.hosts}, before)

    def test_quarantine_guard_rejects_fake_and_malformed_ownership(self):
        task = next(task for task in play_named(RECONCILE)["tasks"]
                    if task["name"] == "Require ownership of the bootstrap scheduling quarantine")
        valid = self.f.node("alpha")
        cases = [("owned", valid, True)]
        absent = copy.deepcopy(valid)
        absent["spec"]["taints"] = copy.deepcopy(CONTROLLER_TAINTS)
        absent["metadata"]["labels"].pop("cvp.novirmor.io/bootstrap-quarantine")
        cases.append(("absent", absent, True))
        for field, values in (("label", [None, "false", True]), ("value", [None, "false", True]),
                              ("effect", [None, "NoExecute", "PreferNoSchedule"])):
            for value in values:
                node = copy.deepcopy(valid)
                target = node["metadata"]["labels"] if field == "label" else node["spec"]["taints"][1]
                key = "cvp.novirmor.io/bootstrap-quarantine" if field == "label" else field
                if value is None:
                    target.pop(key)
                else:
                    target[key] = value
                cases.append((f"{field}-{value}", node, False))
        duplicate = copy.deepcopy(valid)
        duplicate["spec"]["taints"].append(copy.deepcopy(duplicate["spec"]["taints"][1]))
        cases.append(("duplicate", duplicate, False))
        tasks = []
        for name, node, accepted in cases:
            tasks.extend([
                {"ansible.builtin.set_fact": {"guard_rejected": False,
                    "selected_nodes": {"results": [{"item": "alpha", "resources": [node]}]}}},
                {"name": "Exercise quarantine guard " + name, "block": [task],
                 "rescue": [{"ansible.builtin.set_fact": {"guard_rejected": True}}]},
                {"ansible.builtin.assert": {"that": "guard_rejected == " + str(not accepted).lower(),
                                            "fail_msg": "Wrong quarantine decision: " + name}},
            ])
        self.success(self.f.run(plays=[{"hosts": "alpha", "gather_facts": False, "tasks": tasks}]))

    def test_unowned_quarantine_aborts_reconciliation_before_any_patch_or_release(self):
        node = self.f.node("gamma")
        del node["metadata"]["labels"]["cvp.novirmor.io/bootstrap-quarantine"]
        self.f.set_node("gamma", node)
        self.failure(self.f.run(), "bootstrap quarantine does not match")
        self.assert_owned_locks()
        self.assertNotIn("patch-attempt", [row["phase"] for row in self.f.events()])

    def test_real_server_and_agent_templates_register_only_owned_bootstrap_taint(self):
        tasks = []
        for role in ("k3s_server", "k3s_agent"):
            tasks.append({"name": "Render actual " + role + " registration config",
                          "ansible.builtin.template": {
                              "src": str(ROLES / role / "templates/config.yaml.j2"),
                              "dest": str(self.f.root / (role + "-{{ inventory_hostname }}.yaml")), "mode": "0600"}})
        self.success(self.f.run(plays=[{"hosts": "wireguard", "gather_facts": False, "tasks": tasks}]))
        for role in ("k3s_server", "k3s_agent"):
            for host in self.f.hosts:
                with self.subTest(role=role, host=host):
                    config = yaml.safe_load((self.f.root / f"{role}-{host}.yaml").read_text())
                    self.assertEqual(config["node-taint"], ["cvp.novirmor.io/bootstrap=true:NoSchedule"])
                    self.assertEqual(config["node-label"], ["cvp.novirmor.io/bootstrap-quarantine=true"]
                                     + self.f.hostvars[host]["k3s_node_labels"])
                    self.assertEqual(config["node-name"], host)


if __name__ == "__main__":
    unittest.main()
