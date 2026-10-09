#!/usr/bin/env python3
"""The distribution artifacts: cvp.platform collection and cvp-platform wheel.

The collection is built from the repository tree, installs with
ansible-galaxy, and its playbooks syntax-check from the installed collection
path (roles resolve as collection roles). The wheel exposes the operator CLI
entry points and the VERSION-locked metadata. Both must stay in version
lockstep with the repository.
"""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text().strip()
STAGED_COMMIT = "f" * 40


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=600, **kwargs)


class CollectionBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(tempfile.mkdtemp(prefix="cvp-collection-"))
        result = run([sys.executable, "-B", str(ROOT / "scripts/build-collection"),
                      "--output", str(cls.output), "--commit", STAGED_COMMIT])
        assert result.returncode == 0, result.stdout + result.stderr
        cls.tarball = cls.output / f"cvp-platform-{VERSION}.tar.gz"

    def test_tarball_is_stamped_and_carries_the_runtime_payload(self):
        self.assertTrue(self.tarball.is_file())
        with tarfile.open(self.tarball) as archive:
            members = {member.name: member for member in archive.getmembers()}
            manifest = json.loads(archive.extractfile("MANIFEST.json").read())
            platform_commit = archive.extractfile("PLATFORM_COMMIT").read().decode().strip()
            platform_version = archive.extractfile("PLATFORM_VERSION").read().decode().strip()
        info = manifest["collection_info"]
        self.assertEqual((info["namespace"], info["name"], info["version"]),
                         ("cvp", "platform", VERSION))
        self.assertEqual(platform_commit, STAGED_COMMIT)
        self.assertEqual(platform_version, VERSION)
        expected = [
            "README.md", "PLATFORM_VERSION", "PLATFORM_COMMIT",
            "roles/k3s_server/tasks/main.yml", "roles/k3s_server/files/cvp-lifecycle.py",
            "roles/k3s_server/files/cvp-k3s-config-check.py", "roles/wireguard/files/cvp-wireguard-state",
            "roles/firewall/files/cvp-admin-access-check", "roles/base/tasks/activate-service.yml",
            "ansible/defaults/inventory.yml", "ansible/defaults/group_vars/all.yml",
            "ansible/ansible.cfg", "ansible/requirements.yml",
            "ansible/playbooks/site.yml", "ansible/playbooks/verify.yml", "ansible/playbooks/probe.yml",
            "ansible/playbooks/restore-k3s.yml", "ansible/playbooks/validate-inventory.yml",
            "ansible/playbooks/onboard-preflight.yml", "ansible/playbooks/load-operator-config.yml",
            "scripts/cvp_node.py", "scripts/cvp_init.py", "scripts/cvp_instance.py",
            "scripts/cvp_wrapper_common.py", "scripts/bootstrap-flux", "scripts/node-bootstrap.sh",
            "scripts/cvp-topology.py", "scripts/cluster-manifest-inputs",
            "tests/policy/helpers.rego", "tests/policy/secrets.rego", "VERSION",
            "cluster/infrastructure/policy/base/namespaces.yaml",
            "cluster/flux-system/reconciliation.yaml",
            "tofu/tailscale/resources.tf", "tofu/cloudflare/.terraform.lock.hcl", "tasks/ops.yml",
            "templates/instance/Taskfile.yml", "examples/instance/inventory/hosts.yml",
        ]
        for name in expected:
            self.assertIn(name, members, f"missing from collection: {name}")
        for forbidden in ("ansible/playbooks/test-labels.yml", "ansible/playbooks/test-templates.yml",
                          "ansible/playbooks/tasks/test-invalid-node-tags.yml",
                          "ansible/playbooks/test_node_patches.py",
                          "scripts/test-init.py", "scripts/test_host_network_security.py",
                          "tofu/cloudflare/.terraform",
                          "tofu/tailscale/.terraform"):
            self.assertFalse(any(name == forbidden or name.startswith(forbidden + "/") for name in members),
                             f"excluded content shipped: {forbidden}")

    def test_collection_installs_and_playbooks_resolve_from_it(self):
        collections = self.output / "installed"
        result = run(["ansible-galaxy", "collection", "install", str(self.tarball),
                      "-p", str(collections), "--force"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installed = collections / "ansible_collections/cvp/platform"
        self.assertTrue((installed / "ansible/playbooks/site.yml").is_file())
        self.assertTrue((installed / "scripts/cvp_node.py").is_file())
        # Third-party collections the playbooks need, installed side by side
        # (--force: a satisfying copy elsewhere on the machine must not make
        # this isolated path incomplete).
        result = run(["ansible-galaxy", "collection", "install", "-r",
                      str(installed / "ansible/requirements.yml"), "-p", str(collections), "--force"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        empty_config = self.output / "empty.cfg"
        empty_config.write_text("# isolated defaults: no repository ansible.cfg\n")
        for playbook in ("site.yml", "verify.yml", "restore-k3s.yml", "validate-inventory.yml"):
            result = run(["ansible-playbook", "--syntax-check",
                          "-i", str(installed / "ansible/defaults/inventory.yml"),
                          "-i", str(ROOT / "examples/instance/inventory/hosts.yml"),
                          str(installed / "ansible/playbooks" / playbook)],
                         cwd=str(self.output),
                         env={"PATH": __import__("os").environ["PATH"],
                              "HOME": __import__("os").environ.get("HOME", ""),
                              "ANSIBLE_CONFIG": str(empty_config),
                              "ANSIBLE_COLLECTIONS_PATH": str(collections)})
            self.assertEqual(result.returncode, 0,
                             f"installed playbook {playbook} failed syntax check:\n"
                             + result.stdout + result.stderr)


class WheelBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(tempfile.mkdtemp(prefix="cvp-wheel-"))
        result = run(["uv", "build", "--out-dir", str(cls.output)], cwd=ROOT)
        assert result.returncode == 0, result.stdout + result.stderr
        cls.wheel = next(cls.output.glob("cvp_platform-*.whl"))
        cls.sdist = next(cls.output.glob("cvp_platform-*.tar.gz"))

    def test_wheel_carries_the_cli_modules_entry_points_and_version(self):
        with zipfile.ZipFile(self.wheel) as wheel:
            names = wheel.namelist()
            for module in ("cvp_init.py", "cvp_node.py", "cvp_instance.py",
                           "cvp_wrapper_common.py", "cvp_export_kubeconfig.py", "cvp_tofu_operation.py"):
                self.assertIn(module, names)
            self.assertNotIn("test-init.py", names)
            metadata = wheel.read("cvp_platform-" + VERSION + ".dist-info/METADATA").decode()
            self.assertIn(f"Version: {VERSION}", metadata)
            entry_points = wheel.read("cvp_platform-" + VERSION + ".dist-info/entry_points.txt").decode()
            for entry in ("cvp-init = cvp_init:main", "cvp-node = cvp_node:main",
                          "cvp-instance = cvp_instance:main", "cvp-export-kubeconfig = cvp_export_kubeconfig:main",
                          "cvp-tofu = cvp_tofu_operation:main"):
                self.assertIn(entry, entry_points)

    def test_sdist_can_be_built_from_and_reports_the_locked_version(self):
        with tarfile.open(self.sdist) as sdist:
            self.assertIn(f"cvp_platform-{VERSION}/VERSION", sdist.getnames())
            metadata = sdist.extractfile(f"cvp_platform-{VERSION}/PKG-INFO").read().decode()
            self.assertIn(f"Version: {VERSION}", metadata)

    def test_version_file_agrees_with_the_unreleased_changelog(self):
        header = [line for line in (ROOT / "CHANGELOG.md").read_text().splitlines()
                  if line.startswith("## [")][0]
        self.assertIn(f"[{VERSION}]", header,
                      "VERSION must match the unreleased CHANGELOG version")

    def test_installed_entry_points_run_outside_the_repository(self):
        # The uvx bootstrap path: the wheel installed standalone, with no
        # repository checkout beside it. Import-time file reads must fall back
        # to package metadata.
        environment = self.output / "toolvenv"
        result = run(["uv", "venv", str(environment), "--python", sys.executable])
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run(["uv", "pip", "install", "--python", str(environment / "bin/python"), str(self.wheel)])
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run([str(environment / "bin/cvp-instance"), "--help"], cwd=str(self.output))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cvp-instance", result.stdout)
        result = run([str(environment / "bin/cvp-node"), "--help"], cwd=str(self.output))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
