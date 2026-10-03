"""Offline regression tests for the actual site.yml patch template."""

import json
from pathlib import Path
from typing import Any, cast
import unittest

from jinja2.nativetypes import NativeEnvironment
import yaml


SITE = yaml.safe_load(Path(__file__).with_name("site.yml").read_text())
TASK = next(task for task in SITE[-1]["tasks"] if task["name"] == "Compute patches for selected inventory nodes")
TEMPLATE = TASK["vars"]["node_patch"]
CONFLICT_TASK = next(task for task in SITE[-1]["tasks"] if task["name"] == "Refuse to adopt unowned taints")


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
        self.assertEqual(SITE[0]["hosts"], "wireguard")
        self.assertEqual(SITE[0]["connection"], "local")
        self.assertEqual(SITE[0]["tasks"][0]["vars"]["node_tag_validation_hosts"],
                         "{{ ansible_play_hosts_all }}")
        self.assertEqual(SITE[-1]["hosts"], "wireguard")
        self.assertEqual(SITE[-1]["vars"]["tag_target_nodes"], "{{ ansible_play_hosts_all }}")
        for task in SITE[-1]["tasks"]:
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


if __name__ == "__main__":
    unittest.main()
