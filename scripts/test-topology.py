#!/usr/bin/env python3
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/cvp-topology.py"
SPEC = importlib.util.spec_from_file_location("cvp_topology", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TOPOLOGY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOPOLOGY)
STORAGE = "/var/lib/rancher/k3s/storage"
INGRESS_LABELS = ["cvp.io/ingress=true", "svccontroller.k3s.cattle.io/enablelb=true",
                  "svccontroller.k3s.cattle.io/lbpool=public"]


def topology():
    groups = {"wireguard": ["alpha", "beta", "gamma"], "k3s_servers": ["alpha"],
              "k3s_agents": ["beta", "gamma"], "ingress": ["alpha"]}
    hosts = {}
    for index, name in enumerate(groups["wireguard"], 1):
        hosts[name] = {
            "node_name": name, "k3s_role": "server" if name == "alpha" else "agent",
            "k3s_server_init": name == "alpha", "k3s_cluster_init_host": "alpha",
            "k3s_server_host": "alpha", "k3s_datastore": "etcd",
            "wireguard_peers_group": "wireguard", "wireguard_address": f"10.77.0.{index}",
            "wireguard_public_key": base64.b64encode(bytes([index]) * 32).decode(),
            "k3s_node_labels": list(INGRESS_LABELS) if name == "alpha" else [],
            "k3s_node_taints": [], "storage_enabled": True,
            "storage_mountpoint": STORAGE, "k3s_default_local_storage_path": STORAGE,
        }
    return {"groups": groups, "hosts": hosts}


def cluster_nodes(data, target: str | None = "gamma"):
    return [{"metadata": {"name": name, "labels": {
        "node-role.kubernetes.io/control-plane": "true"} if host["k3s_role"] == "server" else {}},
        "status": {"addresses": [{"type": "InternalIP", "address": host["wireguard_address"]}],
                   "conditions": [{"type": "Ready", "status": "True"}]}}
        for name, host in data["hosts"].items() if name != target]


def make_server(data, name):
    data["groups"]["k3s_agents"].remove(name)
    data["groups"]["k3s_servers"].append(name)
    data["hosts"][name]["k3s_role"] = "server"


class TopologyTests(unittest.TestCase):
    def test_valid_etcd_sqlite_and_empty_development_inventory(self):
        data = topology()
        TOPOLOGY.validate_topology(data)
        for host in data["hosts"].values():
            host["k3s_datastore"] = "sqlite"
        TOPOLOGY.validate_topology(data)
        empty = {"groups": {}, "hosts": {}}
        TOPOLOGY.validate_topology(empty, allow_empty=True)
        with self.assertRaisesRegex(ValueError, "nonempty"):
            TOPOLOGY.validate_topology(empty)

    def test_invalid_host_fields(self):
        cases = {
            "node_name": [None, "other"], "k3s_role": [None, "server", ["agent", "server"]],
            "k3s_server_init": [None, "false", 0, True],
            "k3s_cluster_init_host": [None, "", "beta", "gamma"],
            "k3s_server_host": [None, "", "beta", "missing"],
            "k3s_datastore": [None, "mysql", "sqlite"], "wireguard_peers_group": [None, "ingress"],
            "wireguard_address": [None, "10.77.0.1", "10.77.0.0", "10.77.0.255", "10.78.0.3",
                                  "10.77.0.3/24", "::1", "224.0.0.1", "127.0.0.1", "0.1.2.3",
                                  "240.0.0.1", "255.255.255.255", "169.254.0.1", "010.77.0.3"],
            "wireguard_public_key": [None, "", "x" * 44,
                                     base64.b64encode(bytes(31)).decode(),
                                     base64.b64encode(bytes(33)).decode(),
                                     topology()["hosts"]["alpha"]["wireguard_public_key"],
                                     base64.b64encode(bytes(32)).decode()[:-2] + "B="],
            "storage_enabled": [None, "true"], "storage_mountpoint": [None, "/other"],
            "k3s_default_local_storage_path": [None, "/other", "relative", "/storage/../storage"],
            "k3s_node_labels": [None, "flag", ["a=b", "a=c"], ["cvp.io/role=agent"],
                                ["cvp.io/bootstrap-quarantine=false"], ["cvp.io/bootstrap=true"]],
            "k3s_node_taints": [None, ["a:NoSchedule", "a:NoExecute"],
                                ["cvp.io/bootstrap=false:NoSchedule"],
                                ["cvp.io/bootstrap-quarantine:NoExecute"]],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    data = topology()
                    data["hosts"]["gamma"][field] = value
                    with self.assertRaises(ValueError):
                        TOPOLOGY.validate_topology(data)

    def test_missing_and_duplicate_role_membership(self):
        for flag in ("k3s_role", "k3s_server_init"):
            data = topology()
            del data["hosts"]["beta"][flag]
            with self.assertRaises(ValueError):
                TOPOLOGY.validate_topology(data)
        for group, names in (
            ("k3s_servers", []), ("k3s_servers", ["alpha", "gamma"]),
            ("k3s_servers", ["alpha", "outside"]), ("k3s_agents", ["beta"]),
            ("k3s_agents", ["beta", "gamma", "gamma"]),
            ("ingress", []), ("ingress", ["alpha", "beta"]), ("ingress", ["outside"]),
        ):
            with self.subTest(group=group, names=names):
                data = topology()
                data["groups"][group] = names
                with self.assertRaises(ValueError):
                    TOPOLOGY.validate_topology(data)

    def test_init_count_and_datastore_contract(self):
        for duplicate in (False, True):
            data = topology()
            make_server(data, "beta")
            data["hosts"]["alpha"]["k3s_server_init"] = duplicate
            data["hosts"]["beta"]["k3s_server_init"] = duplicate
            with self.assertRaisesRegex(ValueError, "exactly one"):
                TOPOLOGY.validate_topology(data)
        data = topology()
        make_server(data, "beta")
        for host in data["hosts"].values():
            host["k3s_datastore"] = "sqlite"
        with self.assertRaisesRegex(ValueError, "sqlite requires exactly one"):
            TOPOLOGY.validate_topology(data)

    def test_common_storage_path_even_when_storage_disabled(self):
        data = topology()
        data["hosts"]["gamma"].update(storage_enabled=False, storage_mountpoint="/unused")
        TOPOLOGY.validate_topology(data)
        data["hosts"]["gamma"]["k3s_default_local_storage_path"] = "/other"
        with self.assertRaisesRegex(ValueError, "consistent"):
            TOPOLOGY.validate_topology(data)

    def test_ingress_requires_each_placement_label_with_its_expected_value(self):
        for label in INGRESS_LABELS:
            key = label.split("=", 1)[0]
            for replacement in (None, key, key + "=", key + "=false", key + "=private", key + "=True"):
                with self.subTest(label=label, replacement=replacement):
                    data = topology()
                    labels = data["hosts"]["alpha"]["k3s_node_labels"]
                    labels.remove(label)
                    if replacement is not None:
                        labels.append(replacement)
                    with self.assertRaisesRegex(ValueError, "ingress node must declare"):
                        TOPOLOGY.validate_topology(data)

    def test_non_ingress_nodes_reject_contradictory_placement_intent(self):
        for labels in (
            INGRESS_LABELS,
            ["cvp.io/ingress=true"], ["cvp.io/ingress="], ["cvp.io/ingress"],
            ["cvp.io/ingress=True"],
            *([key + suffix] for key in ("svccontroller.k3s.cattle.io/enablelb",
                                        "svccontroller.k3s.cattle.io/lbpool")
              for suffix in ("", "=", "=true", "=false", "=public", "=private")),
        ):
            with self.subTest(labels=labels):
                data = topology()
                data["hosts"]["beta"]["k3s_node_labels"] = list(labels)
                with self.assertRaisesRegex(ValueError, "non-ingress nodes must omit"):
                    TOPOLOGY.validate_topology(data)

    def test_non_ingress_false_and_unrelated_labels_remain_supported(self):
        data = topology()
        data["hosts"]["beta"]["k3s_node_labels"] = [
            "cvp.io/ingress=false", "cvp.io/compute=true",
            "svccontroller.k3s.cattle.io/needs_reconcile=",
        ]
        TOPOLOGY.validate_topology(data)

    def test_coordinated_ingress_relocation_requires_group_and_labels_to_move_together(self):
        data = topology()
        data["groups"]["ingress"] = ["beta"]
        with self.assertRaisesRegex(ValueError, "non-ingress nodes must omit"):
            TOPOLOGY.validate_topology(data)
        data["hosts"]["alpha"]["k3s_node_labels"] = ["cvp.io/ingress=false"]
        with self.assertRaisesRegex(ValueError, "ingress node must declare"):
            TOPOLOGY.validate_topology(data)
        data["hosts"]["beta"]["k3s_node_labels"] = list(INGRESS_LABELS)
        TOPOLOGY.validate_topology(data)

    def test_onboard_new_agent_and_idempotent_retry(self):
        data = topology()
        TOPOLOGY.validate_onboard(data, "gamma", "", cluster_nodes(data))
        nodes = cluster_nodes(data, target=None)
        nodes[-1]["status"]["conditions"][0]["status"] = "False"
        TOPOLOGY.validate_onboard(data, "gamma", "", nodes)

    def test_server_confirmation_and_no_initialization(self):
        data = topology()
        make_server(data, "gamma")
        nodes = cluster_nodes(data)
        TOPOLOGY.validate_onboard(data, "gamma", "gamma", nodes)
        TOPOLOGY.validate_onboard(data, "gamma", "gamma", cluster_nodes(data, target=None))
        for target, confirmation in (("gamma", ""), ("gamma", "beta"), ("gamma", True),
                                     ("alpha", "alpha"), ("beta", "beta"), (None, "")):
            with self.subTest(target=target, confirmation=confirmation):
                with self.assertRaises(ValueError):
                    TOPOLOGY.validate_onboard_intent(data, target, confirmation)
        for host in data["hosts"].values():
            host["k3s_server_host"] = "gamma"
        with self.assertRaisesRegex(ValueError, "existing designated server"):
            TOPOLOGY.validate_onboard_intent(data, "gamma", "gamma")

    def test_membership_ready_roles_and_ips_are_exact(self):
        data = topology()
        original = cluster_nodes(data)
        cases = [[], original[1:], original[:1], original + [original[0]]]
        for name in ("outside", "gamma"):
            extra = copy.deepcopy(original[0])
            extra["metadata"]["name"] = name
            cases.append(original + [extra])
        for path, value in (
            (("metadata", "labels"), {}),
            (("metadata", "labels"), {"node-role.kubernetes.io/etcd": "true"}),
            (("metadata", "labels"), {"node-role.kubernetes.io/control-plane": "", "cvp.io/role": "agent"}),
            (("metadata", "deletionTimestamp"), "2026-01-01T00:00:00Z"),
            (("status", "conditions"), [{"type": "Ready", "status": "False"}]),
            (("status", "conditions"), []),
            (("status", "addresses"), [{"type": "ExternalIP", "address": "10.77.0.1"}]),
            (("status", "addresses"), [{"type": "InternalIP", "address": "10.77.0.99"}]),
        ):
            nodes = copy.deepcopy(original)
            nodes[0][path[0]][path[1]] = value
            cases.append(nodes)
        for nodes in cases:
            with self.subTest(nodes=nodes):
                with self.assertRaises(ValueError):
                    TOPOLOGY.validate_onboard(data, "gamma", "", nodes)

    def test_agent_onboarding_does_not_hide_other_server_changes(self):
        data = topology()
        make_server(data, "beta")
        nodes = cluster_nodes(data)
        TOPOLOGY.validate_onboard(data, "gamma", "", nodes)
        with self.assertRaisesRegex(ValueError, "missing"):
            TOPOLOGY.validate_onboard(data, "gamma", "", nodes[:1])
        nodes[1]["metadata"]["labels"] = {}
        with self.assertRaisesRegex(ValueError, "role differs"):
            TOPOLOGY.validate_onboard(data, "gamma", "", nodes)

    def test_cli_is_stdlib_only_and_does_not_echo_bad_input(self):
        data = topology()
        nodes = cluster_nodes(data)
        nodes[0]["status"]["addresses"][0]["address"] = "SECRET-MUST-NOT-APPEAR"
        result = subprocess.run(
            [sys.executable, "-S", "-B", str(SCRIPT), "onboard"],
            input=json.dumps({"topology": data, "target": "gamma", "nodes": nodes}),
            text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "invalid topology or API input\n")
        self.assertNotIn("SECRET-MUST-NOT-APPEAR", result.stdout + result.stderr)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="cvp-topology-")
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.playbooks = self.directory / "ansible/playbooks"
        self.playbooks.mkdir(parents=True)
        (self.directory / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("ANSIBLE_", "CVP_"))}
        self.env.update(ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), ANSIBLE_NOCOLOR="1",
                        XDG_CONFIG_HOME=str(self.directory / "config"))
        self.sudo_marker = self.directory / "sudo-called"
        sudo = self.directory / "sudo"
        sudo.write_text(f"#!/bin/sh\ntouch '{self.sudo_marker}'\nexit 99\n")
        sudo.chmod(0o700)
        self.env["ANSIBLE_BECOME_EXE"] = str(sudo)
        self.data = topology()
        self.api_log = self.directory / "api-log"
        self.env["CVP_TEST_API_LOG"] = str(self.api_log)

    def inventory(self, data):
        defaults = {"k3s_datastore", "k3s_node_taints", "storage_enabled",
                    "storage_mountpoint", "k3s_default_local_storage_path", "wireguard_peers_group"}
        hosts = {name: {key: value for key, value in host.items()
                        if key not in defaults or value != topology()["hosts"][name][key]}
                 for name, host in data["hosts"].items()}
        result = {"all": {"vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable},
                          "children": {name: {"hosts": {host: hosts.get(host, {}) for host in members}}
                                       for name, members in data["groups"].items()}}}
        path = self.directory / "inventory.json"
        path.write_text(json.dumps(result))
        return path

    def run_play(self, data=None, *, onboard=False, validate_inventory=False,
                 expected=None, check=False, empty=False, extra=None):
        data = data or self.data
        inventory = self.inventory(data)
        if validate_inventory:
            playbook = ROOT / "ansible/playbooks/validate-inventory.yml"
        elif onboard:
            playbook = ROOT / "ansible/playbooks/onboard-preflight.yml"
        else:
            playbook = self.playbooks / "test.json"
            playbook.write_text(json.dumps([
                {"import_playbook": str(ROOT / "ansible/playbooks/load-operator-config.yml")},
                {"name": "Exercise real global controller validation", "hosts": "localhost" if empty else "wireguard",
                 "gather_facts": False, "become": True, "tasks": [
                     {"name": "Validate topology", "ansible.builtin.include_tasks":
                      str(ROOT / "ansible/playbooks/tasks/validate-topology.yml")},
                     {"name": "Prove secret fields were not serialized", "ansible.builtin.assert": {"that": [
                         "'tailscale_auth_key' not in (cvp_topology_data | to_json)",
                         "'wireguard_private_key' not in (cvp_topology_data | to_json)"]}},
                 ]},
            ]))
        result = subprocess.run(
            ["ansible-playbook", "-i", str(ROOT / "ansible/inventory/hosts.yml"), "-i", str(inventory),
             str(playbook), "--limit", "localhost" if empty else "gamma",
             "-e", json.dumps(extra or ({"cvp_onboard_node": "gamma", "cvp_onboard_server_confirm": ""}
                                       if onboard else {"cvp_topology_allow_empty": empty})),
             *(["--check"] if check else [])], env=self.env, text=True, capture_output=True, timeout=90)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, expected is None, output)
        if expected:
            self.assertIn(expected, output)
        self.assertFalse(self.sudo_marker.exists(), output)
        self.assertNotIn("SECRET-MUST-NOT-APPEAR", output)
        return output

    def stub_api(self, nodes, ready=True):
        fixtures = self.directory / "nodes.json"
        fixtures.write_text(json.dumps(nodes))
        self.env["CVP_TEST_NODES"] = str(fixtures)
        collection = self.directory / "collections/ansible_collections/kubernetes/core/plugins/modules"
        collection.mkdir(parents=True, exist_ok=True)
        (collection / "k8s_info.py").write_text(
            "from ansible.module_utils.basic import AnsibleModule\n"
            "import json, os\n"
            "def main():\n"
            "    module = AnsibleModule(argument_spec=dict(kubeconfig=dict(required=True), "
            "api_version=dict(required=True), kind=dict(required=True)), supports_check_mode=True)\n"
            "    with open(os.environ['CVP_TEST_API_LOG'], 'a') as log:\n"
            "        log.write(json.dumps(module.params) + '\\n')\n"
            "    with open(os.environ['CVP_TEST_NODES']) as source:\n"
            "        module.exit_json(changed=False, resources=json.load(source))\n"
            "if __name__ == '__main__':\n"
            "    main()\n")
        self.env["ANSIBLE_COLLECTIONS_PATH"] = str(self.directory / "collections")
        k3s = self.directory / "k3s"
        k3s.write_text(
            f"#!{sys.executable}\nimport json, os, sys\n"
            "with open(os.environ['CVP_TEST_API_LOG'], 'a') as log:\n"
            "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            f"print({'ok' if ready else 'not ready'!r})\n")
        k3s.chmod(0o700)
        self.data["hosts"]["alpha"].update(k3s_bin_path=str(k3s), ansible_become=False)

    def test_real_controller_defaults_limit_check_mode_and_no_sudo(self):
        self.data["hosts"]["alpha"]["tailscale_auth_key"] = "SECRET-MUST-NOT-APPEAR"
        self.data["hosts"]["alpha"]["wireguard_private_key"] = "{{ undefined_secret_should_not_be_evaluated }}"
        self.run_play()
        self.run_play(check=True)

    def test_real_controller_rejects_unselected_invalid_hosts(self):
        cases = [
            ("k3s_server_init", False, "exactly one"),
            ("k3s_server_init", "true", "explicit boolean"),
            ("k3s_role", "agent", "k3s_role"),
            ("wireguard_address", "10.77.0.3", "unique"),
            ("wireguard_public_key", self.data["hosts"]["gamma"]["wireguard_public_key"], "unique"),
            ("storage_mountpoint", "/other", "storage_mountpoint"),
            ("k3s_cluster_init_host", "", "explicitly configured"),
            ("k3s_node_taints", ["cvp.io/bootstrap=true:NoSchedule"], "reserved"),
        ]
        for field, value, expected in cases:
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                data["hosts"]["alpha"][field] = value
                self.run_play(data, expected=expected, check=True)

    def test_empty_default_inventory_is_development_only(self):
        data = {"groups": {}, "hosts": {}}
        self.run_play(data, empty=True)
        self.run_play(data, empty=True, extra={"cvp_topology_allow_empty": False}, expected="nonempty")

    def test_real_controller_global_partition_ingress_and_storage_contract(self):
        for group, members, expected in (
            ("k3s_servers", ["alpha", "beta"], "partition"),
            ("k3s_agents", ["gamma"], "partition"),
            ("k3s_servers", ["alpha", "outside"], "partition"),
            ("ingress", [], "exactly one ingress"),
            ("ingress", ["alpha", "beta"], "exactly one ingress"),
            ("ingress", ["outside"], "subset"),
        ):
            with self.subTest(group=group, members=members):
                data = copy.deepcopy(self.data)
                data["groups"][group] = members
                self.run_play(data, expected=expected)
        data = copy.deepcopy(self.data)
        data["hosts"]["alpha"].update(storage_enabled=False, k3s_default_local_storage_path="/other")
        self.run_play(data, expected="must be consistent")
        data = copy.deepcopy(self.data)
        del data["hosts"]["alpha"]["k3s_server_init"]
        self.run_play(data, expected="explicit boolean")

    def test_real_controller_sqlite_and_duplicate_init(self):
        make_server(self.data, "beta")
        self.data["hosts"]["beta"]["k3s_server_init"] = True
        self.run_play(expected="exactly one k3s_server_init")
        self.data["hosts"]["beta"]["k3s_server_init"] = False
        for host in self.data["hosts"].values():
            host["k3s_datastore"] = "sqlite"
        self.run_play(expected="sqlite requires exactly one")

    def test_inventory_validation_rejects_unselected_ingress_conflicts_without_host_access(self):
        self.env["ANSIBLE_SSH_EXECUTABLE"] = self.env["ANSIBLE_BECOME_EXE"]
        for host in self.data["hosts"].values():
            host.update(ansible_connection="ssh", ansible_host="must-not-contact.invalid")
        cases = [("alpha", []), ("beta", list(INGRESS_LABELS)),
                 ("beta", ["svccontroller.k3s.cattle.io/enablelb=false"]),
                 ("beta", ["svccontroller.k3s.cattle.io/lbpool=public"])]
        for check in (False, True):
            for name, labels in cases:
                with self.subTest(check=check, name=name, labels=labels):
                    data = copy.deepcopy(self.data)
                    data["hosts"][name]["k3s_node_labels"] = labels
                    self.run_play(data, validate_inventory=True, check=check,
                                  expected="ingress node must declare" if name == "alpha" else "non-ingress nodes must omit")

    def test_inventory_validation_accepts_coordinated_ingress_relocation_without_host_access(self):
        self.env["ANSIBLE_SSH_EXECUTABLE"] = self.env["ANSIBLE_BECOME_EXE"]
        for host in self.data["hosts"].values():
            host.update(ansible_connection="ssh", ansible_host="must-not-contact.invalid")
        self.data["groups"]["ingress"] = ["beta"]
        self.data["hosts"]["alpha"]["k3s_node_labels"] = ["cvp.io/ingress=false"]
        self.data["hosts"]["beta"]["k3s_node_labels"] = list(INGRESS_LABELS)
        self.run_play(validate_inventory=True)
        self.run_play(validate_inventory=True, check=True)

    def test_public_onboarding_rejects_ingress_conflicts_before_api_access(self):
        self.stub_api(cluster_nodes(self.data))
        for name, labels in (("alpha", []), ("beta", list(INGRESS_LABELS))):
            with self.subTest(name=name):
                data = copy.deepcopy(self.data)
                data["hosts"][name]["k3s_node_labels"] = labels
                self.run_play(data, onboard=True,
                              expected="ingress node must declare" if name == "alpha" else "non-ingress nodes must omit")
                self.assertFalse(self.api_log.exists())

    def test_unselected_operator_storage_overrides_are_validated(self):
        config = self.directory / "operator.json"
        config.write_text(json.dumps({"cvp_operator_hosts": {"alpha": {"storage_mountpoint": "/other"}}}))
        self.env["CVP_OPERATOR_CONFIG_FILE"] = str(config)
        self.run_play(expected="storage_mountpoint")

    def test_public_onboarding_reads_readyz_and_all_nodes_from_designated_server(self):
        self.stub_api(cluster_nodes(self.data))
        output = self.run_play(onboard=True, check=True)
        self.assertIn("gamma -> alpha", output)
        calls = [json.loads(line) for line in self.api_log.read_text().splitlines()]
        self.assertEqual(calls, [
            ["kubectl", "--kubeconfig=/etc/rancher/k3s/k3s.yaml", "--request-timeout=30s", "get", "--raw=/readyz"],
            {"kubeconfig": "/etc/rancher/k3s/k3s.yaml", "api_version": "v1", "kind": "Node"},
        ])

    def test_public_onboarding_fails_before_api_on_invalid_intent_or_topology(self):
        self.stub_api(cluster_nodes(self.data))
        self.run_play(onboard=True, extra={"cvp_onboard_node": "alpha", "cvp_onboard_server_confirm": "alpha"},
                      expected="must not initialize")
        self.assertFalse(self.api_log.exists())
        make_server(self.data, "gamma")
        self.run_play(onboard=True, expected="requires cvp_onboard_server_confirm")
        self.assertFalse(self.api_log.exists())

    def test_public_onboarding_rejects_failed_readiness_and_missing_server(self):
        self.stub_api(cluster_nodes(self.data), ready=False)
        self.run_play(onboard=True, expected="Read control plane readiness")
        self.assertEqual(len(self.api_log.read_text().splitlines()), 1)
        self.stub_api([])
        self.run_play(onboard=True, expected="missing an existing inventory node")

    def test_public_onboarding_checks_unexpected_server_and_existing_target_ip(self):
        nodes = cluster_nodes(self.data)
        extra = copy.deepcopy(nodes[0])
        extra["metadata"]["name"] = "unconfirmed-server"
        self.stub_api(nodes + [extra])
        self.run_play(onboard=True, expected="unexpected node or unconfirmed server")
        nodes = cluster_nodes(self.data, target=None)
        nodes[-1]["status"]["addresses"][0]["address"] = "10.77.0.99"
        self.stub_api(nodes)
        self.run_play(onboard=True, expected="InternalIP differs")
        self.stub_api(cluster_nodes(self.data, target=None))
        self.run_play(onboard=True)


if __name__ == "__main__":
    unittest.main()
