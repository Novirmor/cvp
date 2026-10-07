#!/usr/bin/env python3
"""Controller-side tests for cvp_node.py (node-new, node-bootstrap, node-join).

`new` runs against a temporary inventory with the real validate-inventory
playbook. `bootstrap` and `join` run with stubbed ansible/ssh executables that
record their argv, so no host is ever contacted.
"""
import base64
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
    if not executable or os.environ.get("CVP_NODE_TEST_ANSIBLE_PYTHON"):
        raise
    interpreter = shlex.split(Path(executable).resolve().read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_NODE_TEST_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "scripts/cvp_node.py"
SHIM = ROOT / "scripts/onboard-node"


def generated_host_key():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
        return path.with_suffix(".pub").read_text().split()[1]


# Fixture host public keys, generated per run (no key material in the repository).
HOST_KEY = generated_host_key()
OTHER_KEY = generated_host_key()

STUB = """#!{python}
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CVP_TEST_CALLS"], "a") as stream:
    stream.write(json.dumps([name, *args]) + "\\n")
joined = " ".join(args)
fail = os.environ.get("CVP_TEST_FAIL", "")
if fail and fail in name + " " + joined:
    sys.exit(3)
if name == "ansible":
    if os.environ.get("CVP_TEST_ANSIBLE_FAIL"):
        sys.exit(4)
    print("node | CHANGED | rc=0 >>\\nroot")
elif name == "ssh-keyscan":
    key = os.environ.get("CVP_TEST_SCAN_KEY", "")
    print(args[-1] + " ssh-ed25519 " + key)
elif name in ("ssh", "scp") and os.environ.get("CVP_TEST_SSH_FAIL"):
    sys.exit(255)
"""


def fingerprint(key):
    result = subprocess.run(["ssh-keygen", "-lf", "-"], input=f"x ssh-ed25519 {key}\n",
                            text=True, capture_output=True, check=True)
    return result.stdout.split()[1]


class NodeLifecycleTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory(prefix="cvp-node-")
        self.addCleanup(workspace.cleanup)
        self.directory = Path(workspace.name)
        self.inventory = self.directory / "inventory/hosts.yml"
        self.inventory.parent.mkdir()
        shutil.copyfile(ROOT / "examples/instance/inventory/hosts.yml", self.inventory)
        self.home = self.directory / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        self.ssh_key = self.home / ".ssh/cvp-ops"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "cvp-ops", "-f", str(self.ssh_key)],
                       check=True)
        self.public_key = self.ssh_key.with_suffix(".pub").read_text().strip()
        self.calls = self.directory / "calls"
        self.stubs = self.directory / "stubs"
        self.stubs.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("CVP_", "ANSIBLE_"))}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"),
                        XDG_STATE_HOME=str(self.home / ".local/state"), CVP_TEST_CALLS=str(self.calls),
                        ANSIBLE_NOCOLOR="1", ANSIBLE_LOCAL_TEMP=str(self.directory / "ansible-tmp"),
                        PYTHONDONTWRITEBYTECODE="1")

    # -- helpers ---------------------------------------------------------

    def cli(self, *args, success=True, expected=None, stub=False, env=None):
        environment = dict(self.env, **(env or {}))
        if stub:
            environment["PATH"] = f"{self.stubs}{os.pathsep}{environment['PATH']}"
        result = subprocess.run([sys.executable, "-B", str(CLI), *args], cwd=ROOT, env=environment,
                                text=True, capture_output=True, timeout=180)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, success, output)
        if expected:
            self.assertIn(expected, output)
        return output

    def install_stubs(self, *names):
        for name in names:
            path = self.stubs / name
            path.write_text(STUB.format(python=sys.executable))
            path.chmod(0o755)

    def recorded(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def playbooks(self):
        return [Path(next(arg for arg in call if arg.endswith(".yml") and "playbooks" in arg)).name
                for call in self.recorded() if call[0] == "ansible-playbook"]

    def new(self, node, *extra, write=True, **kwargs):
        args = ["new", node, "--inventory", str(self.inventory), "--virt", "vm",
                "--ssh-source", "203.0.113.10/32", "--tailscale-auth-key-env", "SYNTHETIC_TS_KEY", *extra]
        return self.cli(*args, *(["--write"] if write else []),
                        env={"SYNTHETIC_TS_KEY": "synthetic-ts-key"}, **kwargs)

    def first_host(self):
        return self.new("server1", "--ssh", "203.0.113.20", "--mesh-address", "10.77.0.1",
                        "--ssh-key", str(self.ssh_key))

    def worker(self, name="worker1", *extra, **kwargs):
        return self.new(name, "--ssh", "203.0.113.21", *extra, **kwargs)

    def host_vars(self, node):
        return yaml.safe_load((self.inventory.parent / "host_vars" / f"{node}.yml").read_text())

    def operator(self):
        return yaml.safe_load((self.home / ".config/cvp/operator.yml").read_text())

    def trust(self, host, key=HOST_KEY):
        with open(self.home / ".ssh/known_hosts", "a") as stream:
            stream.write(f"{host} ssh-ed25519 {key}\n")

    def join(self, node, *extra, **kwargs):
        return self.cli("join", node, "--confirm", node, "--inventory", str(self.inventory), *extra,
                        stub=True, env={"SYNTHETIC_TS_KEY": "synthetic-ts-key", **kwargs.pop("env", {})}, **kwargs)

    # -- node-new --------------------------------------------------------

    def test_first_host_and_worker_validate_with_real_inventory_rules(self):
        self.first_host()
        self.worker()
        inventory = yaml.safe_load(self.inventory.read_text())["all"]
        self.assertEqual(inventory["vars"]["k3s_cluster_init_host"], "server1")
        self.assertEqual(inventory["vars"]["k3s_server_host"], "server1")
        self.assertEqual(set(inventory["children"]["wireguard"]["hosts"]), {"server1", "worker1"})
        self.assertEqual(set(inventory["children"]["k3s_agents"]["hosts"]), {"worker1"})
        self.assertEqual(set(inventory["children"]["ingress"]["hosts"]), {"server1"})
        server, worker = self.host_vars("server1"), self.host_vars("worker1")
        self.assertTrue(server["k3s_server_init"])
        self.assertIn("svccontroller.k3s.cattle.io/lbpool=public", server["k3s_node_labels"])
        self.assertEqual(worker["wireguard_address"], "10.77.0.2")
        self.assertEqual(worker["ansible_private_key_file"], str(self.ssh_key))
        self.assertEqual(worker["k3s_node_labels"], ["cvp.novirmor.io/compute=true"])
        operator = self.operator()["cvp_operator_hosts"]["worker1"]
        key_file = Path(operator["wireguard_private_key"]["file"])
        self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(operator["firewall_ssh_ipv4_source_cidrs"], ["203.0.113.10/32"])
        from cvp_node import wireguard_public_key
        self.assertEqual(wireguard_public_key(key_file.read_text().strip()), worker["wireguard_public_key"])
        self.assertEqual(len(base64.b64decode(worker["wireguard_public_key"])), 32)

    def test_dry_run_changes_nothing(self):
        before = self.inventory.read_text()
        output = self.new("server1", "--ssh", "203.0.113.20", "--mesh-address", "10.77.0.1",
                          "--ssh-key", str(self.ssh_key), write=False)
        self.assertIn("Dry run only", output)
        self.assertEqual(self.inventory.read_text(), before)
        self.assertFalse((self.inventory.parent / "host_vars").exists())
        self.assertFalse((self.home / ".config/cvp").exists())

    def test_failed_validation_rolls_back_every_file(self):
        self.first_host()
        before = self.inventory.read_text()
        operator_before = (self.home / ".config/cvp/operator.yml").read_text()
        # Existing host's environment reference is unresolved, so validation fails.
        self.cli("new", "worker1", "--inventory", str(self.inventory), "--virt", "vm", "--ssh", "203.0.113.21",
                 "--ssh-source", "203.0.113.10/32", "--tailscale-auth-key-env", "WORKER_TS", "--write",
                 env={"WORKER_TS": "synthetic"}, success=False, expected="no changes were kept")
        self.assertEqual(self.inventory.read_text(), before)
        self.assertEqual((self.home / ".config/cvp/operator.yml").read_text(), operator_before)
        self.assertFalse((self.inventory.parent / "host_vars/worker1.yml").exists())
        self.assertFalse((self.home / ".config/cvp/keys/worker1.wg-private").exists())

    def test_new_rejects_unsafe_or_ambiguous_input(self):
        self.new("server1", "--ssh", "203.0.113.20", "--ssh-key", str(self.ssh_key),
                 success=False, expected="explicit --mesh-address")
        self.new("server1", "--ssh", "203.0.113.20", "--mesh-address", "10.77.0.1", "--ssh-key",
                 str(self.ssh_key), "--role", "agent", success=False, expected="must be a server")
        self.cli("new", "server1", "--inventory", str(self.inventory), "--virt", "vm", "--ssh", "203.0.113.20",
                 "--mesh-address", "10.77.0.1", "--ssh-key", str(self.ssh_key), "--ssh-source", "0.0.0.0/0",
                 success=False, expected="single-address")
        self.first_host()
        self.worker("worker1", "--mesh-address", "10.78.0.5", success=False, expected="inside the existing mesh")
        self.worker("worker1", "--mesh-address", "10.77.0.1", success=False, expected="already assigned")
        self.worker("server1", success=False, expected="already in the inventory")

    # -- node-join -------------------------------------------------------

    def test_first_host_join_runs_stages_in_order_and_is_resumable(self):
        self.first_host()
        self.install_stubs("ansible-playbook", "ansible", "ssh-keyscan")
        self.join("server1", success=False, expected="--host-key-fingerprint")
        self.join("server1", "--host-key-fingerprint", fingerprint(OTHER_KEY), success=False,
                  env={"CVP_TEST_SCAN_KEY": HOST_KEY}, expected="did not present the expected host key")
        self.assertFalse((self.home / ".ssh/known_hosts").exists())
        self.join("server1", "--host-key-fingerprint", fingerprint(HOST_KEY), env={"CVP_TEST_SCAN_KEY": HOST_KEY},
                  expected="Join verified for server1")
        self.assertIn(f"203.0.113.20 ssh-ed25519 {HOST_KEY}", (self.home / ".ssh/known_hosts").read_text())
        self.assertEqual(self.playbooks(), ["validate-inventory.yml", "probe.yml", "site.yml",
                                            "probe-wireguard.yml", "verify.yml"])
        self.calls.unlink()
        self.join("server1", expected="nothing to do")
        self.assertEqual(self.recorded(), [])

    def test_worker_join_requires_confirmations_and_carries_onboarding_vars(self):
        self.first_host()
        self.worker()
        self.trust("203.0.113.21")
        self.install_stubs("ansible-playbook", "ansible")
        self.cli("join", "worker1", "--confirm", "worker2", "--inventory", str(self.inventory),
                 stub=True, success=False, expected="--confirm worker1")
        self.join("worker1", expected="Join verified for worker1")
        self.assertEqual(self.playbooks(), ["validate-inventory.yml", "probe.yml", "onboard-preflight.yml",
                                            "site.yml", "probe-wireguard.yml", "verify.yml"])
        site = next(call for call in self.recorded() if any(arg.endswith("site.yml") for arg in call))
        self.assertIn('"cvp_onboard_node": "worker1"', " ".join(site))
        self.assertTrue(all("--limit" not in call for call in self.recorded() if "site.yml" in " ".join(call)))

    def test_server_join_requires_quorum_confirmation(self):
        self.first_host()
        self.new("server2", "--ssh", "203.0.113.22", "--role", "server")
        self.trust("203.0.113.22")
        self.install_stubs("ansible-playbook", "ansible")
        self.join("server2", success=False, expected="--server-confirm server2")
        self.assertEqual(self.recorded(), [])
        self.join("server2", "--server-confirm", "server2", expected="Join verified")

    def test_init_server_cannot_join_an_existing_cluster(self):
        self.first_host()
        self.worker()
        self.trust("203.0.113.20")
        self.install_stubs("ansible-playbook", "ansible")
        self.join("server1", success=False, expected="sole inventory node")
        self.assertEqual(self.recorded(), [])

    def test_failed_read_only_stage_resumes_after_completed_site(self):
        self.first_host()
        self.worker()
        self.trust("203.0.113.21")
        self.install_stubs("ansible-playbook", "ansible")
        self.join("worker1", success=False, env={"CVP_TEST_FAIL": "probe-wireguard.yml"})
        self.calls.unlink()
        self.join("worker1", expected="Resuming worker1 after completed stage 'site'")
        self.assertEqual(self.playbooks(), ["validate-inventory.yml", "probe-wireguard.yml", "verify.yml"])

    def test_interrupted_site_requires_review_and_reruns_live_checks(self):
        self.first_host()
        self.worker()
        self.trust("203.0.113.21")
        self.install_stubs("ansible-playbook", "ansible")
        self.join("worker1", success=False, env={"CVP_TEST_FAIL": "site.yml"})
        self.calls.unlink()
        self.join("worker1", success=False, expected="--retry-reviewed")
        self.assertNotIn("site.yml", self.playbooks())
        self.calls.unlink()
        self.join("worker1", "--retry-reviewed", expected="Join verified")
        self.assertEqual(self.playbooks(), ["validate-inventory.yml", "probe.yml", "onboard-preflight.yml",
                                            "site.yml", "probe-wireguard.yml", "verify.yml"])

    def test_changed_inputs_invalidate_completed_stages(self):
        self.first_host()
        self.worker()
        self.trust("203.0.113.21")
        self.install_stubs("ansible-playbook", "ansible")
        self.join("worker1")
        path = self.inventory.parent / "host_vars/worker1.yml"
        path.write_text(path.read_text().replace("k3s_node_taints: []", 'k3s_node_taints: ["x/y:NoSchedule"]'))
        self.calls.unlink()
        self.join("worker1", expected="Join verified")
        self.assertIn("site.yml", self.playbooks())

    def test_preview_stops_after_check_mode_site(self):
        self.first_host()
        self.trust("203.0.113.20")
        self.install_stubs("ansible-playbook", "ansible")
        self.join("server1", "--preview", expected="Preview complete")
        site = [call for call in self.recorded() if "site.yml" in " ".join(call)]
        self.assertEqual(len(site), 1)
        self.assertIn("--check", site[0])
        self.assertNotIn("probe-wireguard.yml", self.playbooks())

    def test_missing_operator_access_requires_a_public_key(self):
        self.first_host()
        self.trust("203.0.113.20")
        self.ssh_key.with_suffix(".pub").unlink()
        self.install_stubs("ansible-playbook", "ansible")
        self.join("server1", success=False, env={"CVP_TEST_ANSIBLE_FAIL": "1"}, expected="task node-bootstrap")
        self.assertNotIn("site.yml", self.playbooks())

    def test_changed_credential_file_stops_between_stages(self):
        self.first_host()
        self.worker()
        self.trust("203.0.113.21")
        self.install_stubs("ansible", "ssh-keyscan")
        key = self.home / ".config/cvp/keys/worker1.wg-private"
        stub = self.stubs / "ansible-playbook"
        stub.write_text(STUB.format(python=sys.executable)
                        + f"if 'probe.yml' in joined:\n    Path({str(key)!r}).write_text('replaced\\n')\n")
        stub.chmod(0o755)
        self.join("worker1", success=False, expected="credential file changed")
        self.assertNotIn("site.yml", self.playbooks())

    def test_onboard_shim_maps_environment_to_join(self):
        self.first_host()
        self.worker()
        self.trust("203.0.113.21")
        self.install_stubs("ansible-playbook", "ansible")
        env = dict(self.env, PATH=f"{self.stubs}{os.pathsep}{self.env['PATH']}",
                   SYNTHETIC_TS_KEY="synthetic-ts-key", CVP_ONBOARD_NODE="worker1")
        result = subprocess.run(["bash", str(SHIM)], cwd=ROOT, env=env, text=True, capture_output=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CVP_ONBOARD_CONFIRM", result.stderr)
        self.assertEqual(self.recorded(), [])
        # The shim targets the default inventory; exercise its argument mapping via a wrapper.
        wrapper = self.stubs / "python3"
        wrapper.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\" --inventory "
                           f"{shlex.quote(str(self.inventory))}\n")
        wrapper.chmod(0o755)
        env["CVP_ONBOARD_CONFIRM"] = "worker1"
        result = subprocess.run(["bash", str(SHIM)], cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("onboard-preflight.yml", self.playbooks())

    # -- node-bootstrap --------------------------------------------------

    def bootstrap(self, *extra, **kwargs):
        env = {"SYNTHETIC_TS_KEY": "synthetic-ts-key", "CVP_TEST_SCAN_KEY": HOST_KEY, **kwargs.pop("env", {})}
        return self.cli("bootstrap", "server1", "--confirm", "server1", "--inventory", str(self.inventory),
                        *extra, stub=True, env=env, **kwargs)

    def test_bootstrap_copies_and_runs_the_script_after_trusting_the_host_key(self):
        self.first_host()
        self.install_stubs("ansible", "ssh", "scp", "ssh-keyscan")
        self.bootstrap(success=False, expected="--host-key-fingerprint")
        self.bootstrap("--host-key-fingerprint", fingerprint(OTHER_KEY), success=False,
                       expected="did not present the expected host key")
        self.assertFalse(any(call[0] in ("scp", "ssh") for call in self.recorded()))
        self.bootstrap("--host-key-fingerprint", fingerprint(HOST_KEY), expected="ready for Ansible")
        self.assertIn(f"203.0.113.20 ssh-ed25519 {HOST_KEY}", (self.home / ".ssh/known_hosts").read_text())
        calls = self.recorded()
        scp = next(call for call in calls if call[0] == "scp")
        self.assertEqual(scp[-2:], [str(ROOT / "scripts/node-bootstrap.sh"), "root@203.0.113.20:cvp-node-bootstrap.sh"])
        self.assertIn("StrictHostKeyChecking=yes", scp)
        run = next(call for call in calls if call[0] == "ssh" and "-O" not in call)
        self.assertEqual(run[-2], "root@203.0.113.20")
        self.assertEqual(run[-1], f"sh cvp-node-bootstrap.sh {shlex.quote(self.public_key)}; status=$?; "
                                  "rm -f cvp-node-bootstrap.sh; exit $status")
        self.assertTrue(any(call[0] == "ssh" and "-O" in call for call in calls), "control master not closed")
        self.assertEqual(calls[-1][0], "ansible")

    def test_bootstrap_runs_with_sudo_for_a_provider_login_user(self):
        self.first_host()
        self.trust("203.0.113.20")
        self.install_stubs("ansible", "ssh", "scp")
        self.bootstrap("--login-user", "admin")
        run = next(call for call in self.recorded() if call[0] == "ssh" and "-O" not in call)
        self.assertEqual(run[-2], "admin@203.0.113.20")
        self.assertTrue(run[-1].startswith("sudo sh cvp-node-bootstrap.sh "))

    def test_bootstrap_fails_when_ops_cannot_log_in_afterwards(self):
        self.first_host()
        self.trust("203.0.113.20")
        self.install_stubs("ansible", "ssh", "scp")
        self.bootstrap(env={"CVP_TEST_ANSIBLE_FAIL": "1"}, success=False, expected="ops could not log in")
        self.calls.unlink()
        self.bootstrap(env={"CVP_TEST_SSH_FAIL": "1"}, success=False, expected="command failed")
        self.assertNotIn("ansible", [call[0] for call in self.recorded()])

    def test_remote_script_validates_its_key_before_touching_the_host(self):
        script = ROOT / "scripts/node-bootstrap.sh"
        for key, expected in (("not-a-key", "not an approved SSH public key type"),
                              ("ssh-ed25519 AAAA\nssh-ed25519 BBBB", "single line"),
                              (self.public_key, "run as root")):
            with self.subTest(key=key[:20]):
                result = subprocess.run(["sh", str(script), key], text=True, capture_output=True, timeout=10)
                if os.getuid() == 0:
                    self.skipTest("the remote script must not run as root in tests")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "scripts"))
    unittest.main()
