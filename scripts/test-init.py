#!/usr/bin/env python3
"""Tests for the `task init` wizard (scripts/cvp_init.py).

Inventory, host-vars, key, and operator-file writes are real; ssh, scp,
ssh-keyscan, ansible, and ansible-playbook are stubs that record their argv, so
no host is contacted. Real inventory validation of what node-new writes is
covered by test-node-lifecycle.py and test-onboarding-path.py.
"""
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
    if not executable or os.environ.get("CVP_INIT_TEST_ANSIBLE_PYTHON"):
        raise
    interpreter = shlex.split(Path(executable).resolve().read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_INIT_TEST_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])

ROOT = Path(__file__).resolve().parent.parent
WIZARD = ROOT / "scripts/cvp_init.py"

STUB = """#!{python}
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CVP_TEST_CALLS"], "a") as stream:
    stream.write(json.dumps([name, *args]) + "\\n")
fail = os.environ.get("CVP_TEST_FAIL", "")
if fail and fail in name + " " + " ".join(args):
    sys.exit(3)
if name == "ansible":
    if Path(os.environ["CVP_TEST_OPS_READY"]).exists():
        print("node | CHANGED | rc=0 | (stdout) root")
    else:
        sys.exit(4)
elif name == "ssh-keyscan":
    print(args[-1] + " ssh-ed25519 " + os.environ["CVP_TEST_SCAN_KEY"])
elif name == "ssh" and "-O" not in args:
    command = args[-1]
    if "SSH_CONNECTION" in command:
        print(os.environ.get("CVP_TEST_SSH_CONNECTION", "203.0.113.10 50000 203.0.113.20 22"))
    elif "cvp-node-bootstrap.sh" in command:
        Path(os.environ["CVP_TEST_OPS_READY"]).touch()
"""


def generated_host_key():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
        return path.with_suffix(".pub").read_text().split()[1]


HOST_KEY = generated_host_key()


def fingerprint(key):
    result = subprocess.run(["ssh-keygen", "-lf", "-"], input=f"x ssh-ed25519 {key}\n",
                            text=True, capture_output=True, check=True)
    return result.stdout.split()[1]


class InitWizardTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory(prefix="cvp-init-")
        self.addCleanup(workspace.cleanup)
        self.directory = Path(workspace.name)
        self.inventory = self.directory / "inventory/hosts.yml"
        self.inventory.parent.mkdir()
        shutil.copyfile(ROOT / "ansible/inventory/hosts.yml", self.inventory)
        shutil.copytree(ROOT / "ansible/inventory/group_vars", self.inventory.parent / "group_vars")
        self.home = self.directory / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        self.ssh_key = self.home / ".ssh/cvp-ops"
        self.keys = self.home / ".config/cvp/keys"
        self.keys.mkdir(parents=True)
        for directory in (self.home / ".config", self.home / ".config/cvp", self.keys):
            directory.chmod(0o700)
        for node in ("server1", "worker1", "server2"):
            path = self.keys / f"{node}.ts-authkey"
            path.write_text(f"tskey-synthetic-{node}\n")
            path.chmod(0o600)
        self.calls = self.directory / "calls"
        stubs = self.directory / "stubs"
        stubs.mkdir()
        for name in ("ansible", "ansible-playbook", "ssh", "scp", "ssh-keyscan"):
            path = stubs / name
            path.write_text(STUB.format(python=sys.executable))
            path.chmod(0o755)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("CVP_", "ANSIBLE_"))}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"),
                        XDG_STATE_HOME=str(self.home / ".local/state"), CVP_TEST_CALLS=str(self.calls),
                        CVP_TEST_SCAN_KEY=HOST_KEY, CVP_TEST_OPS_READY=str(self.directory / "ops-ready"),
                        PATH=f"{stubs}{os.pathsep}{os.environ['PATH']}", ANSIBLE_NOCOLOR="1",
                        ANSIBLE_LOCAL_TEMP=str(self.directory / "ansible-tmp"), PYTHONDONTWRITEBYTECODE="1")

    def wizard(self, *args, success=True, expected=None, env=None):
        result = subprocess.run([sys.executable, "-B", str(WIZARD), "--inventory", str(self.inventory),
                                 "--skip-kubeconfig", *args],
                                cwd=ROOT, env=dict(self.env, **(env or {})), text=True,
                                capture_output=True, timeout=300, stdin=subprocess.DEVNULL)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, success, output)
        if expected:
            self.assertIn(expected, output)
        self.assertNotIn("tskey-synthetic", output)
        return output

    def recorded(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def tools(self):
        return [call[0] for call in self.recorded()]

    def playbooks(self):
        return [Path(next(arg for arg in call if arg.endswith(".yml") and "playbooks/" in arg)).name
                for call in self.recorded() if call[0] == "ansible-playbook"]

    def first_host(self, *extra, **kwargs):
        return self.wizard("--address", "203.0.113.20", "--host-key-fingerprint", fingerprint(HOST_KEY), *extra,
                           **kwargs)

    def host_vars(self, node):
        return yaml.safe_load((self.inventory.parent / "host_vars" / f"{node}.yml").read_text())

    def operator(self):
        return yaml.safe_load((self.home / ".config/cvp/operator.yml").read_text())["cvp_operator_hosts"]

    def test_first_host_runs_end_to_end_from_a_fresh_debian_install(self):
        output = self.first_host(expected="server1 is part of the cluster")
        self.assertIn("Created", output)  # operator key created on first use
        self.assertTrue(self.ssh_key.is_file())
        host = self.host_vars("server1")
        self.assertTrue(host["k3s_server_init"])
        self.assertEqual(host["wireguard_address"], "10.77.0.1")
        self.assertEqual(host["ansible_private_key_file"], str(self.ssh_key))
        # The SSH source is the address the host saw, not a guess.
        self.assertEqual(self.operator()["server1"]["firewall_ssh_ipv4_source_cidrs"], ["203.0.113.10/32"])
        tools = self.tools()
        self.assertLess(tools.index("ssh-keyscan"), tools.index("scp"))
        bootstrap = next(call for call in self.recorded() if call[0] == "ssh" and "cvp-node-bootstrap.sh" in call[-1])
        self.assertEqual(bootstrap[-2], "root@203.0.113.20")
        self.assertIn(self.ssh_key.with_suffix(".pub").read_text().split()[1], bootstrap[-1])
        self.assertEqual([name for name in self.playbooks() if name != "validate-inventory.yml"],
                         ["probe.yml", "site.yml", "probe-wireguard.yml", "verify.yml"])
        self.assertIn(f"203.0.113.20 ssh-ed25519 {HOST_KEY}", (self.home / ".ssh/known_hosts").read_text())

    def test_second_run_adds_a_worker_with_defaults(self):
        self.first_host()
        self.calls.unlink()
        self.wizard("--address", "203.0.113.21", "--host-key-fingerprint", fingerprint(HOST_KEY),
                    env={"CVP_TEST_SSH_CONNECTION": "203.0.113.10 50000 203.0.113.21 22",
                         "CVP_TEST_OPS_READY": str(self.directory / "worker-ready")},
                    expected="worker1 is part of the cluster")
        worker = self.host_vars("worker1")
        self.assertEqual((worker["k3s_role"], worker["wireguard_address"]), ("agent", "10.77.0.2"))
        self.assertIn("onboard-preflight.yml", self.playbooks())

    def test_rerun_skips_completed_steps(self):
        self.first_host()
        self.calls.unlink()
        self.wizard("--node", "server1", expected="nothing to do")
        self.assertNotIn("scp", self.tools())
        self.assertNotIn("ssh-keyscan", self.tools())

    def test_interrupted_join_resumes_only_after_review(self):
        self.first_host(env={"CVP_TEST_FAIL": "site.yml"}, success=False)
        self.calls.unlink()
        self.wizard("--node", "server1", success=False, expected="--retry-reviewed")
        self.assertNotIn("scp", self.tools())
        self.wizard("--node", "server1", "--retry-reviewed", expected="server1 is part of the cluster")

    def test_reaching_the_host_over_tailscale_is_refused(self):
        self.first_host(env={"CVP_TEST_SSH_CONNECTION": "100.100.100.10 50000 203.0.113.20 22"},
                        success=False, expected="must use its public address")
        self.assertFalse((self.inventory.parent / "host_vars/server1.yml").exists())

    def test_wrong_fingerprint_stops_before_any_login(self):
        self.wizard("--address", "203.0.113.20", "--host-key-fingerprint", "SHA256:wrong",
                    success=False, expected="did not present the expected host key")
        self.assertEqual(self.tools(), ["ssh-keyscan"])

    def test_missing_answers_without_a_terminal_name_their_flags(self):
        self.wizard(success=False, expected="pass --address")
        self.wizard("--address", "203.0.113.20", success=False, expected="pass --host-key-fingerprint")
        (self.keys / "server1.ts-authkey").unlink()
        self.first_host(success=False, expected="pass --tailscale-auth-key-file")


if __name__ == "__main__":
    unittest.main()
