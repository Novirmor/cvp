"""Offline regression tests for the actual site.yml patch template."""

import json
import copy
import os
from pathlib import Path
import shlex
import shutil
import sys
from typing import Any, cast
import unittest

try:
    from jinja2.nativetypes import NativeEnvironment
    import jsonpatch
    import yaml
except ImportError:
    executable = shutil.which("ansible-playbook")
    if not executable or os.environ.get("CVP_NODE_PATCH_ANSIBLE_PYTHON"):
        raise
    interpreter = shlex.split(Path(executable).read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_NODE_PATCH_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])


SITE = yaml.safe_load(Path(__file__).with_name("site.yml").read_text())
RECONCILIATION = next(play for play in SITE
                      if play.get("name") == "Reconcile K3s node labels and taints through the Kubernetes API")
TASK = next(task for task in RECONCILIATION["tasks"] if task["name"] == "Compute patches for selected inventory nodes")
TEMPLATE = TASK["vars"]["node_patch"]
CONFLICT_TASK = next(task for task in RECONCILIATION["tasks"] if task["name"] == "Refuse to adopt unowned taints")


def patch_for(node, labels, taints):
    env = NativeEnvironment()
    env.filters["from_json"] = json.loads
    env.filters["to_json"] = json.dumps
    current = node["metadata"].get("labels", {})
    desired_keys = [label.split("=", 1)[0] for label in labels]
    obsolete = [key for key in current if key.startswith("cvp.io/") and key not in desired_keys]
    return cast(list[dict[str, Any]], env.from_string(TEMPLATE).render(
        node_res=node, node_labels=labels, node_taints=taints,
        current_labels=current, obsolete_keys=obsolete,
        taint_ownership_key="cvp.io/managed-taints",
    ))


class NodePatchTests(unittest.TestCase):
    def test_selected_hosts_drive_validation_and_delegated_reconciliation(self):
        validation = next(play for play in SITE if play["name"] == "Validate node tags before configuring hosts")
        loader = next(play for play in SITE if play["name"] == "Load persistent operator configuration")
        self.assertEqual(loader["ansible.builtin.import_playbook"], "load-operator-config.yml")
        self.assertEqual(validation["hosts"], "wireguard")
        self.assertEqual(validation["connection"], "local")
        tags = next(task for task in validation["tasks"] if task["name"] == "Validate selected inventory nodes")
        self.assertEqual(tags["vars"]["node_tag_validation_hosts"],
                         "{{ ansible_play_hosts_all }}")
        self.assertEqual(RECONCILIATION["hosts"], "wireguard")
        self.assertEqual(RECONCILIATION["vars"]["tag_target_nodes"], "{{ ansible_play_hosts_all }}")
        for task in RECONCILIATION["tasks"]:
            if task["name"] in ("Wait for selected nodes to register in the Kubernetes API",
                                "Read the selected cluster nodes",
                                "Apply the node label and taint patches"):
                self.assertEqual(task["delegate_to"], "{{ k3s_server_host }}")

    def test_unowned_conflict_detection(self):
        env = NativeEnvironment()
        expression = env.from_string(CONFLICT_TASK["vars"]["unowned_matching_taints"])
        live = {"item": {"resources": [{"spec": {"taints": [
            {"key": "dedicated", "effect": "NoExecute"},
            {"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule"},
        ]}}]}}
        self.assertEqual(expression.render(**live, desired_identities=["dedicated"], owned_taints=[]),
                         ["dedicated"])
        self.assertEqual(expression.render(**live, desired_identities=["dedicated"],
                                           owned_taints=[{"key": "dedicated", "effect": "NoSchedule"}]),
                         ["dedicated"])
        self.assertEqual(expression.render(**live, desired_identities=["dedicated"],
                                           owned_taints=[{"key": "dedicated", "effect": "NoExecute"}]),
                         [])

    def test_unowned_taints_preserved_and_owned_removed(self):
        node = {
            "metadata": {
                "labels": {"cvp.io/old": "value", "kubernetes.io/os": "linux"},
                "resourceVersion": "13",
                "annotations": {"cvp.io/managed-taints": json.dumps([
                    {"key": "dedicated", "value": "previous", "effect": "NoSchedule"}
                ])},
            },
            "spec": {"taints": [
                {"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule"},
                {"key": "dedicated", "value": "previous", "effect": "NoSchedule"},
                {"key": "controller.io/protected", "effect": "NoExecute"},
            ]},
        }
        ops = patch_for(node, ["cvp.io/new=abc"], ["new=ok:NoExecute"])
        self.assertEqual(ops[0], {"op": "test", "path": "/metadata/resourceVersion", "value": "13"})
        self.assertEqual([op["path"] for op in ops if op["op"] == "remove"],
                         ["/metadata/labels/cvp.io~1old", "/spec/taints/1"])
        self.assertIn({"op": "test", "path": "/spec/taints", "value": node["spec"]["taints"]}, ops)
        self.assertIn({"op": "add", "path": "/spec/taints/-",
                       "value": {"key": "new", "value": "ok", "effect": "NoExecute"}}, ops)
        self.assertEqual(json.loads(ops[-1]["value"]),
                         [{"key": "new", "value": "ok", "effect": "NoExecute"}])
        self.assertNotIn("/spec/taints", [op["path"] for op in ops if op["op"] == "add"])

    def test_idempotent_and_no_empty_taint_replacement(self):
        owned = {"key": "dedicated", "value": "ok", "effect": "NoSchedule"}
        node = {"metadata": {"labels": {"cvp.io/role": "agent"}, "resourceVersion": "19",
                             "annotations": {"cvp.io/managed-taints": json.dumps([owned])}},
                "spec": {"taints": [owned, {"key": "node.kubernetes.io/not-ready", "effect": "NoExecute"}]}}
        self.assertEqual(patch_for(node, ["cvp.io/role=agent"], ["dedicated=ok:NoSchedule"]), [])
        node["metadata"]["annotations"] = {}
        self.assertEqual(patch_for(node, ["cvp.io/role=agent"], []), [])

    def test_new_taints_and_structured_label_value(self):
        node = {"metadata": {"labels": {}, "annotations": {}, "resourceVersion": "25"}, "spec": {}}
        ops = patch_for(node, ["cvp.io/role=agent", 'cvp.io/comment=a"b\\c'],
                        ["dedicated:NoSchedule"])
        self.assertIn({"op": "add", "path": "/spec/taints",
                       "value": [{"key": "dedicated", "value": "", "effect": "NoSchedule"}]}, ops)
        self.assertEqual(ops[0], {"op": "test", "path": "/metadata/resourceVersion", "value": "25"})
        self.assertEqual(ops[1], {"op": "add", "path": "/metadata/labels/cvp.io~1role", "value": "agent"})
        self.assertEqual(ops[2]["value"], 'a"b\\c')

    def test_atomic_quarantine_removal_applies_inventory_and_preserves_controller_state(self):
        quarantine = {"key": "cvp.io/bootstrap", "value": "true", "effect": "NoSchedule"}
        previous = {"key": "dedicated", "value": "old", "effect": "NoExecute"}
        controllers = [{"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule"},
                       {"key": "controller.io/protected", "value": "keep", "effect": "NoExecute"}]
        node = {"metadata": {"resourceVersion": "42", "labels": {
            "cvp.io/bootstrap-quarantine": "true", "cvp.io/old": "true", "kubernetes.io/os": "linux"},
            "annotations": {"cvp.io/managed-taints": json.dumps([previous]), "controller.io/state": "keep"}},
            "spec": {"taints": [controllers[0], previous, quarantine, controllers[1]]}}
        labels = ["cvp.io/role=agent", "cvp.io/compute=true"]
        taints = ["dedicated=new:NoSchedule"]
        ops = patch_for(node, labels, taints)
        final = jsonpatch.apply_patch(node, ops)
        desired = {"key": "dedicated", "value": "new", "effect": "NoSchedule"}
        self.assertEqual(final["spec"]["taints"], controllers + [desired])
        self.assertEqual(final["metadata"]["labels"], {
            "kubernetes.io/os": "linux", "cvp.io/role": "agent", "cvp.io/compute": "true"})
        self.assertEqual(final["metadata"]["annotations"], {
            "cvp.io/managed-taints": json.dumps([desired]), "controller.io/state": "keep"})
        self.assertEqual(patch_for(final, labels, taints), [])
        self.assertIn(quarantine, node["spec"]["taints"])
        for changed in ("version", "taints", "ledger"):
            with self.subTest(changed=changed):
                concurrent = copy.deepcopy(node)
                if changed == "version":
                    concurrent["metadata"]["resourceVersion"] = "43"
                elif changed == "taints":
                    concurrent["spec"]["taints"].append({"key": "another-controller", "effect": "NoExecute"})
                else:
                    concurrent["metadata"]["annotations"]["cvp.io/managed-taints"] = "[]"
                with self.assertRaises(jsonpatch.JsonPatchTestFailed):
                    jsonpatch.apply_patch(concurrent, ops)

    def test_bootstrap_only_patch_does_not_claim_controller_taints(self):
        controller = {"key": "node.kubernetes.io/unreachable", "effect": "NoExecute"}
        node = {"metadata": {"labels": {"cvp.io/bootstrap-quarantine": "true"}, "resourceVersion": "1"},
                "spec": {"taints": [{"key": "cvp.io/bootstrap", "value": "true", "effect": "NoSchedule"},
                                    controller]}}
        final = jsonpatch.apply_patch(node, patch_for(node, ["cvp.io/role=control-plane"], []))
        self.assertEqual(final["spec"]["taints"], [controller])
        self.assertEqual(final["metadata"]["labels"], {"cvp.io/role": "control-plane"})
        self.assertNotIn("annotations", final["metadata"])


if __name__ == "__main__":
    unittest.main()
