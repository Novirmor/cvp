#!/usr/bin/env python3
"""Keep docs/runbooks/nodes.md honest.

The documented `task node-new` commands are executed against a temporary
inventory, and the files they generate must equal the documented reference
examples. Every documented shell snippet must parse and name existing tasks.
"""
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
NODES = ROOT / "docs/runbooks/nodes.md"
CLI = ROOT / "scripts/cvp_node.py"
VALIDATOR = ROOT / "ansible/playbooks/validate-inventory.yml"
DOC_HOME = "/home/operator"


def snippets(path, language):
    return re.findall(r"^```" + re.escape(language) + r"\s*\n(.*?)^```\s*$",
                      path.read_text(), re.MULTILINE | re.DOTALL)


def example(predicate):
    matches = [data for data in (yaml.safe_load(block) for block in snippets(NODES, "yaml"))
               if isinstance(data, dict) and predicate(data)]
    if len(matches) != 1:
        raise AssertionError(f"Expected one matching YAML example in {NODES.name}, found {len(matches)}")
    return matches[0]


def documented_new(node):
    for block in snippets(NODES, "sh"):
        for command in block.replace("\\\n", " ").splitlines():
            words = shlex.split(command)
            if words[:4] == ["task", "node-new", "--", node]:
                return words[3:]
    raise AssertionError(f"No documented task node-new command for {node}")


class OnboardingPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cvp-onboarding-path-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.inventory = self.directory / "inventory/hosts.yml"
        self.inventory.parent.mkdir()
        shutil.copyfile(ROOT / "ansible/inventory/hosts.yml", self.inventory)
        shutil.copytree(ROOT / "ansible/inventory/group_vars", self.inventory.parent / "group_vars")
        self.home = self.directory / "home"
        keys = self.home / ".config/cvp/keys"
        keys.mkdir(parents=True)
        for directory in (self.home / ".config", self.home / ".config/cvp", keys):
            directory.chmod(0o700)
        self.secrets = []
        for node in ("server1", "worker1"):
            secret = f"SYNTHETIC-{node}-TS-KEY-MUST-NOT-APPEAR"
            self.secrets.append(secret)
            path = keys / f"{node}.ts-authkey"
            path.write_text(secret + "\n")
            path.chmod(0o600)
        self.access_marker = self.directory / "host-access-called"
        blocker = self.directory / "host-access-blocked"
        blocker.write_text(f"#!{sys.executable}\nfrom pathlib import Path\n"
                           f"Path({str(self.access_marker)!r}).touch()\nraise SystemExit(99)\n")
        blocker.chmod(0o700)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("ANSIBLE_", "CVP_"))}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"),
                        XDG_STATE_HOME=str(self.home / ".local/state"), PYTHONDONTWRITEBYTECODE="1",
                        ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), ANSIBLE_NOCOLOR="1",
                        ANSIBLE_LOCAL_TEMP=str(self.directory / "ansible-local"),
                        ANSIBLE_SSH_EXECUTABLE=str(blocker), ANSIBLE_BECOME_EXE=str(blocker))

    def run_command(self, argv, *, success=True, expected=None):
        result = subprocess.run(argv, cwd=ROOT, env=self.env, text=True, capture_output=True, timeout=180)
        output = result.stdout + result.stderr
        for secret in self.secrets:
            self.assertNotIn(secret, output, "Synthetic credential appeared in command output")
        self.assertFalse(self.access_marker.exists(), "Controller-only command attempted host access")
        self.assertEqual(result.returncode == 0, success, output)
        if expected:
            self.assertIn(expected, output)
        return result

    def scaffold(self, node):
        args = [arg.replace("$HOME", str(self.home)) for arg in documented_new(node)]
        self.run_command([sys.executable, "-B", str(CLI), "new", *args,
                          "--inventory", str(self.inventory), "--write"])

    def generated(self, path):
        text = path.read_text().replace(str(self.home), DOC_HOME)
        return yaml.safe_load(text)

    def documented_pair(self):
        self.scaffold("server1")
        self.scaffold("worker1")

    def validate(self, *, check=False, success=True, expected=None):
        return self.run_command(["ansible-playbook", "-i", str(self.inventory), str(VALIDATOR),
                                 *(["--check"] if check else [])], success=success, expected=expected)

    def test_documented_commands_generate_the_documented_files(self):
        self.documented_pair()
        self.assertEqual(self.generated(self.inventory), example(lambda data: "all" in data))
        for node in ("server1", "worker1"):
            with self.subTest(node=node):
                generated = self.generated(self.inventory.parent / "host_vars" / f"{node}.yml")
                documented = example(lambda data, node=node: data.get("node_name") == node)
                self.assertEqual(documented.pop("wireguard_public_key"), f"REPLACE_WITH_{node.upper()}_WG_PUBLIC_KEY")
                generated.pop("wireguard_public_key")
                self.assertEqual(generated, documented)
        self.assertEqual(self.generated(self.home / ".config/cvp/operator.yml"),
                         example(lambda data: "cvp_operator_hosts" in data))

    def test_generated_inventory_validates_in_check_mode_without_host_access(self):
        self.documented_pair()
        self.validate()
        self.validate(check=True)

    def test_real_inventory_precedence_exposes_conflicting_group_selection(self):
        self.documented_pair()
        group_path = self.inventory.parent / "group_vars/all.yml"
        defaults = yaml.safe_load(group_path.read_text())
        defaults["k3s_cluster_init_host"] = ""
        group_path.write_text(yaml.safe_dump(defaults, sort_keys=False))
        result = self.run_command(["ansible-inventory", "-i", str(self.inventory), "--list"])
        hostvars = json.loads(result.stdout)["_meta"]["hostvars"]
        for host in ("server1", "worker1"):
            self.assertEqual(hostvars[host]["k3s_cluster_init_host"], "")
        self.validate(success=False, expected="explicitly configured")

    def test_documented_shell_examples_parse_and_reference_existing_tasks(self):
        tasks = yaml.safe_load((ROOT / "Taskfile.yml").read_text())["tasks"]
        for document in (NODES,):
            for block in snippets(document, "sh") + snippets(document, "bash"):
                with self.subTest(document=document.name, snippet=block.splitlines()[0]):
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-n"], input=block,
                                            cwd=ROOT, env={"PATH": os.environ["PATH"]},
                                            text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for name in re.findall(r"\btask\s+([a-z][a-z0-9-]*)", block):
                        self.assertIn(name, tasks, f"Unknown documented task in {document}")


if __name__ == "__main__":
    unittest.main()
