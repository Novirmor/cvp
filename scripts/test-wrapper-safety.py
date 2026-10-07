#!/usr/bin/env python3
"""Adversarial wrapper tests. Every operational executable is a local stub."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = {
    "wireguard": {"hosts": ["worker1", "worker2"]},
    "k3s_agents": {"hosts": ["worker1", "worker2"]},
    "k3s_servers": {"hosts": []},
    "_meta": {"hostvars": {
        name: {
            "node_name": name, "ansible_host": name + ".invalid",
            "node_virtualization": "vm", "k3s_role": "agent", "k3s_server_init": False,
            "wireguard_address": "192.0.2.4", "wireguard_public_key": "fixture",
        } for name in ("worker1", "worker2")
    }},
}
STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["TEST_CALLS"], "a") as log:
    log.write(json.dumps({"tool": pathlib.Path(sys.argv[0]).name, "args": args,
                         "cwd": os.getcwd(), "config": os.getenv("CVP_OPERATOR_CONFIG_FILE"),
                         "config_sha256": os.getenv("CVP_OPERATOR_CONFIG_SHA256")}) + "\n")
tool = pathlib.Path(sys.argv[0]).name
playbook = next((pathlib.Path(a).name for a in args if a.endswith(".yml") and "playbooks" in a), "")
if tool in ("mise", "ansible-inventory", "ansible-playbook", "ansible"):
    if "ansible-inventory" in args or tool == "ansible-inventory":
        print(os.environ["TEST_INVENTORY"])
    if tool == "ansible":
        print("worker1 | CHANGED | rc=0 >>\nroot")
    if os.getenv("TEST_MUTATE_CONFIG") and playbook == "probe.yml":
        pathlib.Path(os.environ["CVP_OPERATOR_CONFIG_FILE"]).write_text(
            '{"cvp_operator_defaults":{"storage_enabled":false}}')
    if os.getenv("TEST_CREATE_CONFIG") and playbook == "probe.yml":
        path = pathlib.Path(os.environ["XDG_CONFIG_HOME"]) / "cvp/operator.yml"
        path.parent.mkdir(parents=True)
        path.write_text('{}')
    if os.getenv("TEST_FAIL_PREFLIGHT") and playbook == "onboard-preflight.yml":
        sys.exit(1)
elif tool == "ssh-keygen" and "-F" in args:
    print(args[args.index("-F") + 1] + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture")
elif tool == "tofu":
    assert args[0].startswith("-chdir=/"), args
    if args[1] == "plan":
        output = pathlib.Path(next(a[5:] for a in args if a.startswith("-out=")))
        assert output.exists() and output.stat().st_mode & 0o777 == 0o600
        assert output.parent.stat().st_mode & 0o777 == 0o700
        output.write_bytes(b"private plan fixture")
        if os.getenv("TEST_RACE_TARGET"):
            pathlib.Path(os.environ["TEST_RACE_TARGET"]).symlink_to(os.environ["TEST_VICTIM"])
        sys.exit(int(os.getenv("TEST_PLAN_RC", "0")))
    if args[1:3] == ["show", "-json"]:
        print(json.dumps({"variables": {"tailnet": {"value": "fixture.invalid"}},
              "prior_state": {"values": {"root_module": {"resources": [{
                  "address": "terraform_data.tailnet_identity", "values": {
                      "input": "fixture.invalid", "triggers_replace": ["fixture.invalid"]}}]}}},
              "resource_changes": [{"type": "tailscale_dns_configuration",
              "change": {"actions": [os.getenv("TEST_DNS_ACTION", "update")]}}]}))
    elif args[1] == "console":
        print(json.dumps(json.dumps(os.getenv("TEST_TAILNET", "fixture.invalid"))))
    elif args[1:3] == ["state", "pull"]:
        resources = []
        if "tailscale-" in args[0] and not os.getenv("TEST_MISSING_IDENTITY"):
            resources = [{"type": "terraform_data", "name": "tailnet_identity", "instances": [{"attributes": {
                "input": {"value": "fixture.invalid"}, "triggers_replace": {"value": ["fixture.invalid"]}}}]}]
        print(json.dumps({"serial": 1, "resources": resources}))
        sys.exit(int(os.getenv("TEST_STATE_RC", "0")))
    elif args[1] == "apply":
        assert pathlib.Path(args[-1]).read_bytes() == b"private plan fixture"
'''


class WrapperSafety(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cvp-wrapper-test-")
        self.work = Path(self.temporary.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        for name in ("tofu", "mise", "ssh-keygen", "ansible-inventory", "ansible-playbook", "ansible"):
            executable = self.bin / name
            executable.write_text(STUB)
            executable.chmod(0o700)
        self.artifacts = self.work / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.backend = self.work / "backend"
        self.backend.mkdir()
        (self.backend / "terraform.tfstate").write_text(json.dumps({
            "backend": {"type": "s3", "config": {"bucket": "fixture", "key": "fixture", "region": "us-east-1"}},
        }))
        self.calls = self.work / "calls"
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("TF_", "CVP_", "TEST_", "AWS_", "TAILSCALE_", "CLOUDFLARE_"))
        }
        self.home = self.work / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh/known_hosts").write_text("worker1.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture\n")
        self.env.update({
            "HOME": str(self.home), "XDG_STATE_HOME": str(self.work / "state"),
            "XDG_CONFIG_HOME": str(self.work / "config"),
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "TEST_CALLS": str(self.calls), "TF_DATA_DIR": str(self.backend),
            "CVP_TOFU_RECOVERY_DIR": str(self.work / "recovery"),
            "TEST_INVENTORY": json.dumps(INVENTORY),
            "CVP_ONBOARD_NODE": "worker1", "CVP_ONBOARD_CONFIRM": "worker1",
            "CVP_ACCESS_NODE": "worker1", "CVP_ACCESS_CONFIRM": "worker1",
        })
        self.public_key = self.work / "operator.pub"
        self.public_key.write_text("ssh-ed25519 cHVibGlj fixture\n")
        self.env["CVP_ACCESS_PUBLIC_KEY_FILE"] = str(self.public_key)

    def tearDown(self):
        self.temporary.cleanup()

    def run_wrapper(self, script, *args, code: int | None = 0):
        result = subprocess.run(
            ["bash", str(ROOT / "scripts" / script), *map(str, args)],
            cwd=self.work, env=self.env, capture_output=True, text=True,
        )
        if code is None:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def tofu(self, operation, *args, root="cloudflare", code: int | None = 0):
        return self.run_wrapper("tofu-operation", root, operation, *args, code=code)

    def logged(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def playbooks(self):
        return [call for call in self.logged() if call["tool"] == "ansible-playbook"]

    def playbook_names(self):
        return [Path(next(a for a in call["args"] if a.endswith(".yml") and "playbooks/" in a)).name
                for call in self.playbooks()]

    def config(self, data):
        path = self.work / "operator.json"
        path.write_text(json.dumps(data))
        self.env["CVP_OPERATOR_CONFIG_FILE"] = str(path)
        return path

    def plan(self, **kwargs):
        path = self.artifacts / "plan"
        self.tofu("plan", "--out", path, **kwargs)
        return path

    def test_private_bound_plan_and_absolute_root(self):
        old = os.umask(0o022)
        try:
            path = self.plan()
        finally:
            os.umask(old)
        metadata = Path(str(path) + ".cvp.json")
        for artifact in (path, metadata):
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        self.tofu("show", path)
        self.tofu("apply", path)
        for call in self.logged():
            self.assertEqual(Path(call["cwd"]).parent, self.work / "recovery")
            self.assertEqual(call["args"][0], "-chdir=" + call["cwd"])
        self.assertEqual(list((self.work / "recovery").iterdir()), [])
        self.assertEqual(set(self.artifacts.iterdir()), {path, metadata})

    def test_plan_binding_rejects_mutations_and_wrong_context(self):
        path = self.plan()
        before = len(self.logged())
        self.tofu("apply", path, root="tailscale", code=None)
        self.env["TF_WORKSPACE"] = "another"
        self.tofu("apply", path, code=None)
        del self.env["TF_WORKSPACE"]
        original = (self.backend / "terraform.tfstate").read_bytes()
        (self.backend / "terraform.tfstate").write_text('{"backend":{"type":"s3","config":{"key":"other"}}}')
        self.tofu("apply", path, code=None)
        (self.backend / "terraform.tfstate").write_bytes(original)
        path.write_bytes(b"modified after review")
        self.tofu("apply", path, code=None)
        self.assertEqual(len(self.logged()), before)

    def test_existing_and_unsafe_outputs_never_clobbered(self):
        victim = self.artifacts / "victim"
        victim.write_text("preserve")
        victim.chmod(0o644)
        link = self.artifacts / "link"
        link.symlink_to(victim)
        for target in (victim, link, self.artifacts):
            self.tofu("state-pull", target, code=None)
            self.tofu("plan", f"-out={target}", code=None)
        self.assertEqual(victim.read_text(), "preserve")
        self.assertFalse(self.logged())

    def test_canonical_paths_and_option_bypasses(self):
        alias = self.work / "repository"
        alias.symlink_to(ROOT, target_is_directory=True)
        traversal = str(ROOT.parent / ".." / ROOT.parent.name / ROOT.name / "artifact")
        for path in (alias / "artifact", Path(traversal)):
            self.tofu("plan", f"-out={path}", code=None)
            self.tofu("state-pull", path, code=None)
        good = f"-out={self.artifacts / 'plan'}"
        for args in (
            [good, "--out=artifact"], [good, good], ["-var-file", good],
            [good, "--target=tailscale_acl.policy"], [good, "-exclude=terraform_data.tailnet_identity"],
            [good, "-refresh-only=false"], [good, "-destroy"], [good, "-lock=false"],
            [good, "-input=true"], [good, "-generate-config-out=artifact"],
        ):
            self.tofu("plan", *args, code=None)
        self.env["TF_CLI_ARGS_plan"] = "--out=artifact"
        self.tofu("plan", good, code=None)
        self.assertFalse(self.logged())

    def test_directory_alias_outside_repo_is_canonicalized(self):
        alias = self.work / "alias"
        alias.symlink_to(self.artifacts, target_is_directory=True)
        self.tofu("plan", f"-out={alias / 'plan'}")
        self.assertTrue((self.artifacts / "plan").is_file())

    def test_no_partial_publication_and_detailed_exit_code(self):
        self.env["TEST_PLAN_RC"] = "1"
        self.plan(code=1)
        self.assertEqual(list(self.artifacts.iterdir()), [])
        self.env["TEST_PLAN_RC"] = "2"
        self.tofu("plan", "-detailed-exitcode", f"-out={self.artifacts / 'plan'}", code=2)
        self.assertTrue((self.artifacts / "plan").is_file())

    def test_publication_race_does_not_follow_symlink(self):
        victim = self.work / "victim"
        victim.write_text("preserve")
        self.env["TEST_VICTIM"] = str(victim)
        self.env["TEST_RACE_TARGET"] = str(self.artifacts / "plan")
        self.plan(code=None)
        self.assertEqual(victim.read_text(), "preserve")
        self.assertEqual(list(self.artifacts.iterdir()), [self.artifacts / "plan"])

    def test_private_atomic_state_and_shared_directory_rejection(self):
        path = self.artifacts / "state"
        self.env["TEST_STATE_RC"] = "1"
        self.tofu("state-pull", path, code=1)
        self.assertEqual(list(self.artifacts.iterdir()), [])
        self.env["TEST_STATE_RC"] = "0"
        self.tofu("state-pull", path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.artifacts.chmod(0o777)
        self.tofu("state-pull", self.artifacts / "other", code=None)

    def test_drift_mode_and_dns_adoption(self):
        self.env["TEST_DNS_ACTION"] = "create"
        self.plan(root="tailscale", code=None)
        self.assertEqual(list(self.artifacts.iterdir()), [])
        self.env["TEST_DNS_ACTION"] = "update"
        path = self.artifacts / "drift"
        self.tofu("drift-plan", f"-out={path}", root="tailscale")
        call = next(call for call in reversed(self.logged()) if call["args"][1] == "plan")
        self.assertIn("-refresh-only", call["args"])
        self.tofu("apply", path, root="tailscale")

    def test_import_argument_handling(self):
        self.tofu("import", "-var", "tailnet=fixture.invalid", "tailscale_acl.policy", "acl", root="tailscale")
        self.assertEqual(self.logged()[-1]["args"][-2:], ["tailscale_acl.policy", "acl"])
        self.tofu("import", "-state-out=artifact", "x", "y", code=None)

    def test_onboarding_uses_same_host_scoped_configuration_everywhere(self):
        path = self.config({
            "cvp_operator_defaults": {"firewall_ssh_ipv4_source_cidrs": ["192.0.2.1/32"]},
            "cvp_operator_hosts": {"worker1": {"storage_device": "/dev/disk/by-id/fixture"}},
        })
        self.run_wrapper("onboard-node")
        calls = [call for call in self.logged() if call["tool"].startswith("ansible")]
        self.assertEqual(self.playbook_names(), ["validate-inventory.yml", "probe.yml", "onboard-preflight.yml",
                                                 "site.yml", "probe-wireguard.yml", "verify.yml"])
        self.assertTrue(all(call["config"] == str(path) for call in calls))
        self.assertEqual(len({call["config_sha256"] for call in calls}), 1)
        self.assertEqual(len(calls[0]["config_sha256"]), 64)
        for name in ("site.yml", "onboard-preflight.yml"):
            call = next(call for call in self.playbooks() if any(a.endswith(f"playbooks/{name}") for a in call["args"]))
            self.assertNotIn("--limit", call["args"])
            extras = [json.loads(call["args"][i + 1]) for i, arg in enumerate(call["args"]) if arg == "-e"]
            self.assertEqual(extras[-1]["cvp_onboard_node"], "worker1")
            self.assertTrue(extras[0]["ansible_ssh_host_key_checking"])

    def test_config_change_after_probe_stops_before_mutation(self):
        self.config({"cvp_operator_defaults": {"storage_enabled": True}})
        self.env["TEST_MUTATE_CONFIG"] = "1"
        self.run_wrapper("onboard-node", code=None)
        self.assertEqual(self.playbook_names()[-1], "probe.yml")
        self.assertNotIn("site.yml", self.playbook_names())

    def test_config_appearance_after_probe_stops_before_mutation(self):
        self.env["TEST_CREATE_CONFIG"] = "1"
        self.run_wrapper("onboard-node", code=None)
        self.assertEqual(self.playbook_names()[-1], "probe.yml")
        self.assertNotIn("site.yml", self.playbook_names())

    def test_fleet_preflight_failure_stops_onboarding(self):
        self.env["TEST_FAIL_PREFLIGHT"] = "1"
        self.run_wrapper("onboard-node", code=None)
        self.assertEqual(self.playbook_names()[-1], "onboard-preflight.yml")
        self.assertNotIn("site.yml", self.playbook_names())

    def test_real_ansible_ssh_precedence_uses_strict_checking_and_selected_identity(self):
        ssh = self.bin / "inert-ssh"
        log = self.work / "ssh-arguments"
        ssh.write_text('#!/usr/bin/env python3\nimport json, os, sys\n'
                       'with open(os.environ["SSH_FIXTURE_LOG"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                       'sys.exit(255)\n')
        ssh.chmod(0o700)
        inventory = self.work / "ssh-inventory.json"
        inventory.write_text(json.dumps({"all": {"hosts": {"fixture": {
            "ansible_host": "fixture.invalid", "ansible_connection": "ssh",
            "ansible_user": "wrong-modern", "ansible_ssh_user": "wrong-legacy",
            "ansible_private_key_file": "/wrong-modern-key", "ansible_ssh_private_key_file": "/wrong-legacy-key",
            "ansible_private_key": "invalid inline private key", "ansible_ssh_private_key": "invalid legacy inline private key",
            "ansible_ssh_host_key_checking": False,
            "ansible_ssh_args": "-o StrictHostKeyChecking=no -o ControlPath=/wrong-master",
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=no",
            "ansible_ssh_extra_args": "-o StrictHostKeyChecking=no",
        }}}}))
        key = self.work / "chosen identity"
        key.write_text("synthetic private key")
        env = {key: value for key, value in self.env.items() if not key.startswith("ANSIBLE_")}
        env.update(PATH=os.environ["PATH"],  # the real ansible, not the wrapper stubs
                   ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), ANSIBLE_HOST_KEY_CHECKING="False",
                   ANSIBLE_SSH_HOST_KEY_CHECKING="False", ANSIBLE_SSH_ARGS="-o StrictHostKeyChecking=no",
                   ANSIBLE_SSH_COMMON_ARGS="-o StrictHostKeyChecking=no", ANSIBLE_SSH_EXTRA_ARGS="-o StrictHostKeyChecking=no",
                   ANSIBLE_SSH_EXECUTABLE=str(ssh), SSH_FIXTURE_LOG=str(log),
                   ANSIBLE_LOCAL_TEMP=str(self.work / "ansible-local"),
                   ANSIBLE_SSH_CONTROL_PATH_DIR=str(self.work / "ssh-control"))
        for user in ("root", "ops"):
            options = subprocess.check_output(["python3", "-B", str(ROOT / "scripts/cvp_wrapper_common.py"),
                                               "ssh-options", user, str(key)], env=env, text=True)
            result = subprocess.run(["ansible", "-i", str(inventory), "fixture", "-m", "ansible.builtin.raw", "-a", "true",
                                     "-e", "ansible_become=false", "-e", options], env=env, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            argv = json.loads(log.read_text().splitlines()[-1])
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertNotIn("StrictHostKeyChecking=no", argv)
            self.assertIn(f'User="{user}"', argv)
            self.assertIn(f'IdentityFile="{key}"', argv)
            self.assertIn("IdentityAgent=none", argv)
            self.assertIn("ControlPath=none", argv)
            self.assertNotIn("/wrong-master", " ".join(argv))

    def test_access_resolves_external_identity_symlinks(self):
        identity = self.work / "operator identity"
        identity.write_text("private fixture")
        alias = self.work / "identity-alias"
        alias.symlink_to(identity)
        self.env["CVP_ACCESS_ROOT_IDENTITY_FILE"] = str(alias)
        self.env["CVP_ACCESS_OPERATOR_IDENTITY_FILE"] = str(alias)
        self.run_wrapper("prepare-node-access")
        remote = [call for call in self.logged() if "-e" in call["args"]]
        self.assertEqual(len(remote), 3)
        for call in remote:
            extra = json.loads(call["args"][-1])
            self.assertEqual(extra["ansible_private_key_file"], str(identity))
            self.assertEqual(extra["ansible_ssh_private_key_file"], str(identity))
            self.assertIn("IdentityAgent=none", extra["ansible_ssh_args"])

    def test_ambient_backend_and_log_overrides_fail_before_tofu(self):
        for key in ("AWS_ENDPOINT_URL_S3", "AWS_S3_ENDPOINT", "AWS_PROFILE", "AWS_CONFIG_FILE",
                    "AWS_SHARED_CREDENTIALS_FILE", "TF_LOG", "TF_LOG_PATH", "TF_LOG_PROVIDER"):
            with self.subTest(key=key):
                self.env[key] = "fixture"
                self.plan(code=None)
                del self.env[key]
        self.assertFalse(self.logged())

    def test_import_requires_matching_established_tailnet(self):
        self.env["TEST_MISSING_IDENTITY"] = "1"
        self.tofu("import", "tailscale_acl.policy", "acl", root="tailscale", code=None)
        del self.env["TEST_MISSING_IDENTITY"]
        self.env["TEST_TAILNET"] = "different.invalid"
        self.tofu("import", "tailscale_acl.policy", "acl", root="tailscale", code=None)
        self.assertFalse(any(call["args"][1] == "import" for call in self.logged()))

    def test_cached_backend_profiles_and_credentials_are_rejected(self):
        for key in ("profile", "shared_config_files", "shared_credentials_files", "shared_credentials_file", "access_key", "secret_key", "token"):
            with self.subTest(key=key):
                config = {"bucket": "fixture", "key": "fixture", "region": "us-east-1", key: "must-not-be-used"}
                (self.backend / "terraform.tfstate").write_text(json.dumps({"backend": {"type": "s3", "config": config}}))
                self.plan(code=None)
        self.assertFalse(self.logged())

    def test_operator_config_rejects_global_and_host_identity_overrides(self):
        for data in (
            {"ansible_host": "wrong.invalid"},
            {"cvp_operator_defaults": {"storage_device": "/dev/vdb"}},
            {"cvp_operator_defaults": {"wireguard_private_key": "fixture"}},
            {"cvp_operator_hosts": {"worker1": {"ansible_host": "wrong.invalid"}}},
            {"cvp_operator_hosts": {"worker1": {"k3s_server_init": True}}},
            {"cvp_operator_hosts": {"worker1": {"node_virtualization": "auto"}}},
            {"cvp_operator_hosts": {"worker1": {"wireguard_address": "192.0.2.99"}}},
            {"cvp_operator_hosts": {"worker1": {"tailscale_extra_up_args": ["--hostname=wrong"]}}},
        ):
            self.config(data)
            self.run_wrapper("onboard-node", code=None)
        self.assertFalse(self.logged())

    def test_operator_config_rejects_unknown_host_and_duplicate_keys(self):
        path = self.config({"cvp_operator_hosts": {"typo": {"storage_enabled": False}}})
        self.run_wrapper("onboard-node", code=None)
        self.assertEqual([call["tool"] for call in self.logged()], ["ansible-inventory"])
        self.calls.unlink()
        path.write_text("cvp_operator_defaults: {}\ncvp_operator_defaults: {}\n")
        self.run_wrapper("onboard-node", code=None)
        self.assertFalse(self.logged())

    def test_config_alias_and_identity_path_containment(self):
        alias = self.work / "repository"
        alias.symlink_to(ROOT, target_is_directory=True)
        for value in (
            alias / "ansible/defaults/group_vars/all.yml",
            ROOT.parent / ".." / ROOT.parent.name / ROOT.name / "ansible/defaults/group_vars/all.yml",
        ):
            self.env["CVP_OPERATOR_CONFIG_FILE"] = str(value)
            self.run_wrapper("onboard-node", code=None)
            self.env["CVP_ACCESS_ROOT_IDENTITY_FILE"] = str(value)
            self.run_wrapper("prepare-node-access", code=None)
        self.assertFalse(self.logged())
        del self.env["CVP_ACCESS_ROOT_IDENTITY_FILE"]
        path = self.config({"cvp_operator_hosts": {}})
        del self.env["CVP_OPERATOR_CONFIG_FILE"]
        self.env["CVP_ONBOARD_SITE_VARS_FILE"] = str(path)
        self.run_wrapper("onboard-node")
        self.assertTrue(all(call["config"] == str(path) for call in self.logged()))


if __name__ == "__main__":
    unittest.main()
