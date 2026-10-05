#!/usr/bin/env python3
import base64
import copy
import json
import os
from pathlib import Path
import re
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
    if not executable or os.environ.get("CVP_ONBOARDING_PATH_ANSIBLE_PYTHON"):
        raise
    interpreter = shlex.split(Path(executable).read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_ONBOARDING_PATH_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "docs/runbooks/ansible-host-bootstrap.md"
ONBOARDING = ROOT / "docs/runbooks/node-onboarding.md"
GROUP_VARS = ROOT / "ansible/inventory/group_vars/all.yml"
VALIDATOR = ROOT / "ansible/playbooks/validate-inventory.yml"


def snippets(path, language):
    return re.findall(r"^```" + re.escape(language) + r"\s*\n(.*?)^```\s*$",
                      path.read_text(), re.MULTILINE | re.DOTALL)


def example(path, predicate):
    candidates = [yaml.safe_load(block) for block in snippets(path, "yaml")]
    matches = [candidate for candidate in candidates if isinstance(candidate, dict) and predicate(candidate)]
    if len(matches) != 1:
        raise AssertionError(f"Expected one matching YAML example in {path}, found {len(matches)}")
    return copy.deepcopy(matches[0])


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    path.chmod(0o600)
    return path


class OnboardingPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cvp-onboarding-path-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.inventory_dir = self.directory / "inventory"
        self.inventory = self.inventory_dir / "hosts.yml"
        self.inventory_data = example(BOOTSTRAP, lambda data: "all" in data)
        self.server = example(BOOTSTRAP, lambda data: data.get("node_name") == "server1")
        self.worker = example(ONBOARDING, lambda data: data.get("node_name") == "worker1")
        self.worker_groups = example(ONBOARDING, lambda data: "wireguard" in data)
        self.operator = example(BOOTSTRAP, lambda data: "cvp_operator_hosts" in data)
        self.worker_operator = example(ONBOARDING, lambda data: "cvp_operator_hosts" in data)
        self.secret_values = []
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("ANSIBLE_", "CVP_"))}
        self.env.update(ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), ANSIBLE_NOCOLOR="1",
                        ANSIBLE_LOCAL_TEMP=str(self.directory / "ansible-local"),
                        ANSIBLE_REMOTE_TEMP=str(self.directory / "ansible-remote"),
                        XDG_CONFIG_HOME=str(self.directory / "config"), PYTHONDONTWRITEBYTECODE="1")
        self.access_marker = self.directory / "host-access-called"
        blocker = self.directory / "host-access-blocked"
        blocker.write_text(f"#!{sys.executable}\nfrom pathlib import Path\n"
                           f"Path({str(self.access_marker)!r}).touch()\nraise SystemExit(99)\n")
        blocker.chmod(0o700)
        self.env.update(ANSIBLE_SSH_EXECUTABLE=str(blocker), ANSIBLE_BECOME_EXE=str(blocker))
        destination = self.inventory_dir / "group_vars/all.yml"
        destination.parent.mkdir(parents=True)
        shutil.copyfile(GROUP_VARS, destination)

    def prepare(self, *, worker=False, literal=False):
        data = copy.deepcopy(self.inventory_data)
        operator = copy.deepcopy(self.operator)
        hostvars = {"server1": copy.deepcopy(self.server)}
        if worker:
            data["all"]["children"] = copy.deepcopy(self.worker_groups)
            hostvars["worker1"] = copy.deepcopy(self.worker)
            operator["cvp_operator_hosts"].update(copy.deepcopy(self.worker_operator["cvp_operator_hosts"]))
        for index, (host, values) in enumerate(hostvars.items(), 1):
            self.assertEqual(values["wireguard_public_key"], f"REPLACE_WITH_{host.upper()}_WG_PUBLIC_KEY")
            values["wireguard_public_key"] = base64.b64encode(bytes([index]) * 32).decode()
            write(self.inventory_dir / "host_vars" / (host + ".yml"), values)
        for host, values in operator["cvp_operator_hosts"].items():
            for key in ("wireguard_private_key", "tailscale_auth_key"):
                reference = values[key]
                self.assertEqual(set(reference), {"env"})
                value = f"SYNTHETIC-SECRET-{host}-{key}-MUST-NOT-APPEAR"
                self.secret_values.append(value)
                self.env[reference["env"]] = value
                if literal:
                    values[key] = value
        write(self.inventory, data)
        operator_path = write(self.directory / "operator.yml", operator)
        self.env["CVP_OPERATOR_CONFIG_FILE"] = str(operator_path)
        return hostvars

    def run_command(self, argv, *, success=True, expected=None):
        result = subprocess.run(argv, cwd=ROOT, env=self.env, text=True, capture_output=True, timeout=90)
        output = result.stdout + result.stderr
        for value in self.secret_values:
            self.assertNotIn(value, output, "Synthetic operator credential appeared in command output")
        self.assertFalse(self.access_marker.exists(), "Controller validation attempted host access or escalation")
        self.assertEqual(result.returncode == 0, success, output)
        if expected:
            self.assertIn(expected, output)
        return result

    def resolved_inventory(self):
        result = self.run_command(["ansible-inventory", "-i", str(self.inventory), "--list"])
        return json.loads(result.stdout)

    def validate(self, *, check=False, success=True, expected=None):
        return self.run_command(["ansible-playbook", "-i", str(self.inventory), str(VALIDATOR),
                                 *(["--check"] if check else [])], success=success, expected=expected)

    def assert_effective_hosts(self, expected):
        inventory = self.resolved_inventory()
        self.assertEqual(set(inventory["wireguard"]["hosts"]), set(expected))
        for host, source in expected.items():
            with self.subTest(host=host):
                row = inventory["_meta"]["hostvars"][host]
                for selection in ("k3s_cluster_init_host", "k3s_server_host"):
                    self.assertNotIn(selection, source)
                    self.assertEqual(row[selection], "server1")
                for key in ("ansible_host", "ansible_private_key_file", "wireguard_address", "wireguard_public_key",
                            "k3s_role", "k3s_server_init", "storage_enabled"):
                    self.assertEqual(row[key], source[key])
                self.assertEqual(row["k3s_datastore"], "etcd")
                self.assertEqual(row["k3s_default_local_storage_path"], "/var/lib/rancher/k3s/storage")
                self.assertEqual(row["storage_mountpoint"], "/var/lib/rancher/k3s/storage")
                self.assertEqual(row["ansible_user"], "ops")
                self.assertIs(row["ansible_become"], True)
        return inventory

    def test_first_host_example_validates_with_real_group_defaults_and_ingress_contract(self):
        hosts = self.prepare()
        inventory = self.assert_effective_hosts(hosts)
        self.assertEqual(inventory["ingress"]["hosts"], ["server1"])
        server = inventory["_meta"]["hostvars"]["server1"]
        self.assertTrue({"cvp.io/ingress=true", "svccontroller.k3s.cattle.io/enablelb=true",
                         "svccontroller.k3s.cattle.io/lbpool=public"}.issubset(server["k3s_node_labels"]))
        self.assertEqual(set(server["tailscale_advertise_tags"]), {"tag:k3s", "tag:k3s-ingress"})
        self.validate()
        self.validate(check=True)

    def test_worker_example_inherits_both_shared_servers_and_preserves_ingress(self):
        hosts = self.prepare(worker=True)
        inventory = self.assert_effective_hosts(hosts)
        self.assertEqual(inventory["k3s_servers"]["hosts"], ["server1"])
        self.assertEqual(inventory["k3s_agents"]["hosts"], ["worker1"])
        self.assertEqual(inventory["ingress"]["hosts"], ["server1"])
        server = inventory["_meta"]["hostvars"]["server1"]
        worker = inventory["_meta"]["hostvars"]["worker1"]
        self.assertEqual(server["k3s_node_labels"], hosts["server1"]["k3s_node_labels"])
        self.assertEqual(worker["k3s_node_labels"], ["cvp.io/compute=true"])
        self.assertEqual(worker["tailscale_advertise_tags"], ["tag:k3s"])
        self.assertEqual(worker["ansible_private_key_file"], server["ansible_private_key_file"])
        self.validate()
        self.validate(check=True)

    def test_literal_operator_credentials_validate_without_output_disclosure(self):
        self.prepare(worker=True, literal=True)
        self.validate()

    def test_real_inventory_precedence_exposes_conflicting_group_selection(self):
        self.prepare(worker=True)
        group_path = self.inventory_dir / "group_vars/all.yml"
        defaults = yaml.safe_load(group_path.read_text())
        defaults["k3s_cluster_init_host"] = ""
        write(group_path, defaults)
        inventory = self.resolved_inventory()
        for host in ("server1", "worker1"):
            self.assertEqual(inventory["_meta"]["hostvars"][host]["k3s_cluster_init_host"], "")
        self.validate(success=False, expected="explicitly configured")

    def test_documented_shell_examples_parse_and_reference_existing_tasks(self):
        tasks = yaml.safe_load((ROOT / "Taskfile.yml").read_text())["tasks"]
        for document in (BOOTSTRAP, ONBOARDING):
            blocks = snippets(document, "sh") + snippets(document, "bash")
            self.assertTrue(blocks, f"No shell examples found in {document}")
            for block in blocks:
                with self.subTest(document=document.name, snippet=block.splitlines()[0]):
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-n"], input=block,
                                            cwd=ROOT, env={"PATH": os.environ["PATH"]},
                                            text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for name in re.findall(r"\btask\s+([a-z][a-z0-9-]*)", block):
                        self.assertIn(name, tasks, f"Unknown documented task in {document}")


if __name__ == "__main__":
    unittest.main()
