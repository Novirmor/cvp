#!/usr/bin/env python3
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import cvp_export_kubeconfig as export

ROOT = export.ROOT
YAML = export.yaml_module(Path(__file__).resolve())
SECRET = "SYNTHETIC-CREDENTIAL-MUST-NOT-APPEAR"

SHIM = '''#!/usr/bin/env python3
import base64
import json
import os
from pathlib import Path
import stat
import sys
import yaml

name = Path(sys.argv[0]).name
args = sys.argv[1:]
log = Path(os.environ["FIXTURE_LOG"])
with log.open("a") as stream:
    stream.write(json.dumps({"command": name, "args": args}) + "\\n")
if name == "ansible-inventory":
    print(Path(os.environ["FIXTURE_INVENTORY"]).read_text())
elif name == "ansible-playbook":
    assert args[args.index("--limit") + 1] == os.environ["CVP_KUBECONFIG_HOST"]
    assert Path(args[args.index("-i") + 1]).is_absolute()
    options = json.loads(args[args.index("-e") + 1])
    assert options["ansible_host_key_checking"] is True
    assert options["ansible_ssh_host_key_checking"] is True
    assert "StrictHostKeyChecking=yes" in options["ansible_ssh_args"]
    assert options["ansible_ssh_common_args"] == ""
    assert options["ansible_ssh_extra_args"] == ""
    assert "ansible_user" not in options and "ansible_become" not in options
    assert os.environ["ANSIBLE_LOG_PATH"] == os.devnull
    stage = Path(os.environ["CVP_KUBECONFIG_STAGING_FILE"])
    assert stat.S_IMODE(stage.stat().st_mode) == 0o600
    assert stat.S_IMODE(stage.parent.stat().st_mode) == 0o700
    stage.write_bytes(base64.b64encode(Path(os.environ["FIXTURE_REMOTE"]).read_bytes()))
    print(Path(os.environ["FIXTURE_REMOTE"]).read_text())
    print("SYNTHETIC-CREDENTIAL-MUST-NOT-APPEAR", file=sys.stderr)
    sys.exit(int(os.environ.get("FIXTURE_ANSIBLE_FAIL", "0")))
else:
    assert name == "kubectl"
    assert len(args) == 5 and args[2:] == ["--request-timeout=15s", "get", "--raw=/readyz"]
    assert args[1] == "--context=" + os.environ["CVP_KUBECONFIG_CONTEXT"]
    path = Path(args[0].split("=", 1)[1])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    data = yaml.safe_load(path.read_bytes())
    assert set(data["clusters"][0]["cluster"]) == {"server", "certificate-authority-data"}
    assert set(data["users"][0]["user"]) == {"client-certificate-data", "client-key-data"}
    assert data["current-context"] == os.environ["CVP_KUBECONFIG_CONTEXT"]
    output = Path(os.environ["CVP_KUBECONFIG_OUTPUT"])
    if os.environ.get("FIXTURE_RACE"):
        output.write_text("concurrent artifact")
    print("SYNTHETIC-CREDENTIAL-MUST-NOT-APPEAR", file=sys.stderr)
    sys.exit(int(os.environ.get("FIXTURE_API_FAIL", "0")))
'''


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificates = tempfile.TemporaryDirectory(prefix="cvp-export-certs-")
        directory = Path(cls.certificates.name)
        cert, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=cvp-fixture", "-addext", "subjectAltName=IP:10.77.0.1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cert, cls.key = cert.read_bytes(), key.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.certificates.cleanup()

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="cvp-export-test-")
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.output = self.directory / "admin.yaml"
        self.log = self.directory / "commands.jsonl"
        self.remote = self.directory / "remote.yaml"
        self.inventory_file = self.directory / "inventory.json"
        self.inventory = {
            "_meta": {"hostvars": {"alpha": {"node_name": "alpha", "k3s_role": "server"},
                                   "beta": {"node_name": "beta", "k3s_role": "server"}}},
            "k3s_servers": {"hosts": ["alpha", "beta"]},
        }
        self.data = {
            "apiVersion": "v1", "kind": "Config", "current-context": "default",
            "clusters": [{"name": "default", "cluster": {
                "server": "https://127.0.0.1:6443",
                "certificate-authority-data": base64.b64encode(self.cert).decode()}}],
            "users": [{"name": "default", "user": {
                "client-certificate-data": base64.b64encode(self.cert).decode(),
                "client-key-data": base64.b64encode(self.key).decode()}}],
            "contexts": [{"name": "default", "context": {"cluster": "default", "user": "default"}}],
        }
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CVP_", "ANSIBLE_", "FIXTURE_"))}
        self.env.update(PATH=f"{self.bin}:{self.env['PATH']}",
                        CVP_KUBECONFIG_HOST="beta", CVP_KUBECONFIG_CONFIRM="beta",
                        CVP_KUBECONFIG_CONTEXT="private-admin", CVP_KUBECONFIG_SERVER="https://10.77.0.2:6443",
                        CVP_KUBECONFIG_OUTPUT=str(self.output), FIXTURE_LOG=str(self.log),
                        FIXTURE_INVENTORY=str(self.inventory_file), FIXTURE_REMOTE=str(self.remote),
                        XDG_CONFIG_HOME=str(self.directory / "config"))
        for name in ("ansible-inventory", "ansible-playbook", "kubectl"):
            executable = self.bin / name
            executable.write_text(SHIM)
            executable.chmod(0o700)

    def run_export(self, *, success=False, arguments=()):
        self.inventory_file.write_text(json.dumps(self.inventory))
        self.remote.write_text(YAML.safe_dump(self.data))
        result = subprocess.run([str(ROOT / "scripts/export-kubeconfig"), *arguments],
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn(self.data["users"][0]["user"].get("client-key-data", "missing-key"),
                         result.stdout + result.stderr)
        self.assertEqual(list(self.directory.glob(".cvp-kubeconfig-*")), [])
        return result

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_export_from_joining_server_preserves_embedded_credentials_and_strips_hooks(self):
        user = self.data["users"][0]["user"]
        user.update(exec={"command": SECRET}, **{"auth-provider": {"name": SECRET},
                    "client-key": SECRET, "client-certificate": SECRET,
                    "token": SECRET, "tokenFile": SECRET})
        self.data["clusters"][0]["cluster"].update({"certificate-authority": SECRET,
                                                            "proxy-url": SECRET, "tls-server-name": SECRET})
        self.data["contexts"][0]["context"]["namespace"] = SECRET
        self.run_export(success=True)
        published = YAML.safe_load(self.output.read_bytes())
        self.assertEqual(published["users"][0]["user"], {key: user[key] for key in (
            "client-certificate-data", "client-key-data")})
        self.assertEqual(published["clusters"][0]["cluster"]["certificate-authority-data"],
                         self.data["clusters"][0]["cluster"]["certificate-authority-data"])
        self.assertEqual(published["clusters"][0]["cluster"]["server"], self.env["CVP_KUBECONFIG_SERVER"])
        self.assertEqual(published["current-context"], "private-admin")
        self.assertEqual(len({published[field][0]["name"] for field in ("clusters", "users", "contexts")}), 3)
        self.assertEqual(published["extensions"][0]["extension"]["source-host"], "beta")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SECRET, self.output.read_text())
        commands = self.commands()
        self.assertEqual([row["command"] for row in commands], ["ansible-inventory", "ansible-playbook", "kubectl"])
        self.assertFalse(Path(commands[-1]["args"][0].split("=", 1)[1]).exists())
        self.assertNotIn(self.data["users"][0]["user"]["client-key-data"], self.log.read_text())

    def test_confirmation_context_host_and_extra_arguments_fail_before_transport(self):
        for key, value in (("CVP_KUBECONFIG_CONFIRM", "alpha"), ("CVP_KUBECONFIG_CONTEXT", ""),
                           ("CVP_KUBECONFIG_CONTEXT", "{{ unsafe }}"), ("CVP_KUBECONFIG_HOST", "all:beta")):
            with self.subTest(key=key):
                saved = self.env[key]
                self.env[key] = value
                self.run_export()
                self.env[key] = saved
                self.assertEqual(self.commands(), [])
        self.run_export(arguments=("--check",))
        self.assertEqual(self.commands(), [])

    def test_yaml_fallback_uses_pinned_ansible_python(self):
        env = dict(self.env, PATH=os.environ["PATH"])
        result = subprocess.run(["python3", "-S", "-B", str(ROOT / "scripts/cvp_export_kubeconfig.py"), "--check"],
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("takes no arguments", result.stderr)
        self.assertEqual(self.commands(), [])

    def test_wrong_role_node_identity_or_non_ssh_never_slurps(self):
        cases = [{"k3s_servers": {"hosts": ["alpha"]}}, {"k3s_agents": {"hosts": ["beta"]}},
                 {"beta": {"hosts": []}}]
        for changes in cases:
            original = copy.deepcopy(self.inventory)
            self.inventory.update(changes)
            self.run_export()
            self.inventory = original
        for field, value in (("node_name", "alpha"), ("k3s_role", "agent"), ("ansible_connection", "local")):
            self.inventory["_meta"]["hostvars"]["beta"][field] = value
            self.run_export()
            self.inventory["_meta"]["hostvars"]["beta"] = {"node_name": "beta", "k3s_role": "server"}
        self.assertTrue(all(row["command"] == "ansible-inventory" for row in self.commands()))

    def test_unsafe_endpoints_fail_before_transport(self):
        for endpoint in ("http://10.77.0.2:6443", "https://10.77.0.2", "https://10.77.0.2:443",
                         "https://user@10.77.0.2:6443", "https://10.77.0.2:6443/", "https://10.77.0.2:6443?",
                         "https://10.77.0.2:6443#", "https://8.8.8.8:6443", "https://127.0.0.1:6443",
                         "https://[::1]:6443", "https://169.254.0.1:6443", "https://{{ host }}:6443"):
            with self.subTest(endpoint=endpoint):
                self.env["CVP_KUBECONFIG_SERVER"] = endpoint
                self.run_export()
        self.assertEqual(self.commands(), [])

    def test_private_dns_ipv6_and_tailnet_addresses(self):
        for endpoint in ("https://[fd00::1]:6443", "https://100.64.0.1:6443"):
            self.assertEqual(export.server_url(endpoint), endpoint)
        with patch.object(export.socket, "getaddrinfo", return_value=[(0, 0, 0, "", ("10.77.0.1", 6443))]):
            self.assertEqual(export.server_url("https://k3s.mesh.example:6443"), "https://k3s.mesh.example:6443")
        with patch.object(export.socket, "getaddrinfo", return_value=[(0, 0, 0, "", ("8.8.8.8", 6443))]):
            with self.assertRaises(ValueError):
                export.server_url("https://k3s.mesh.example:6443")

    def test_output_aliases_overwrite_relative_repo_and_writable_parent_fail(self):
        target = self.directory / "existing"
        target.write_text("existing data")
        alias = self.directory / "alias"
        alias.symlink_to(target)
        repo_alias = self.directory / "repo"
        repo_alias.symlink_to(ROOT, target_is_directory=True)
        parent_alias = self.directory / "parent-alias"
        parent_alias.symlink_to(self.directory, target_is_directory=True)
        writable = self.directory / "writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        for path in (target, alias, Path("relative.yaml"), ROOT / "never-export.yaml",
                     repo_alias / "never-export.yaml", parent_alias / "new.yaml", writable / "new.yaml"):
            with self.subTest(path=path):
                self.env["CVP_KUBECONFIG_OUTPUT"] = str(path)
                self.run_export()
        self.assertEqual(target.read_text(), "existing data")
        self.assertEqual(self.commands(), [])

    def test_invalid_remote_configs_never_reach_api_or_publish(self):
        original = copy.deepcopy(self.data)
        cases = []
        for payload, key, value in (("cluster", "insecure-skip-tls-verify", True),
                                    ("cluster", "certificate-authority-data", "invalid"),
                                    ("user", "client-key-data", base64.b64encode(SECRET.encode()).decode()),
                                    ("user", "client-certificate-data", "")):
            data = copy.deepcopy(original)
            data["clusters" if payload == "cluster" else "users"][0][payload][key] = value
            cases.append(data)
        for field in ("clusters", "users", "contexts"):
            data = copy.deepcopy(original)
            data[field].append(copy.deepcopy(data[field][0]))
            cases.append(data)
        data = copy.deepcopy(original)
        data["contexts"][0]["context"]["user"] = "wrong"
        cases.append(data)
        data = copy.deepcopy(original)
        del data["users"][0]["user"]["client-key-data"]
        cases.append(data)
        for data in cases:
            self.data = data
            self.run_export()
            self.assertFalse(self.output.exists())
        self.assertNotIn("kubectl", [row["command"] for row in self.commands()])

    def test_transport_and_api_failure_clean_staging_without_secret_logs(self):
        for key in ("FIXTURE_ANSIBLE_FAIL", "FIXTURE_API_FAIL"):
            self.env[key] = "1"
            result = self.run_export()
            self.assertFalse(self.output.exists())
            self.assertIn("check", result.stderr)
            del self.env[key]

    def test_exclusive_publication_rejects_concurrent_output(self):
        self.env["FIXTURE_RACE"] = "1"
        self.run_export()
        self.assertEqual(self.output.read_text(), "concurrent artifact")

    def test_malformed_yaml_duplicate_keys_and_mismatched_certificate_key_are_sanitized(self):
        for raw in (b"not: [valid: yaml", b"kind: Config\nkind: " + SECRET.encode(), b"[]"):
            with self.assertRaisesRegex(ValueError, "embedded") as failure:
                export.transform(raw, "admin", "https://10.77.0.1:6443", "beta", self.directory, YAML)
            self.assertNotIn(SECRET, str(failure.exception))
        other = self.directory / "other.key"
        subprocess.run(["openssl", "genrsa", "-out", str(other), "2048"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.data["users"][0]["user"]["client-key-data"] = base64.b64encode(other.read_bytes()).decode()
        self.run_export()
        self.assertFalse(self.output.exists())

    def test_real_kubectl_rejects_fixture_tls_hostname_without_logging_credentials(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        directory = Path(self.certificates.name)
        tls.load_cert_chain(directory / "cert.pem", directory / "key.pem")
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        endpoint = f"https://127.0.0.1:{server.server_port}"
        config = self.directory / "tls.yaml"
        export.private_write(config, export.transform(YAML.safe_dump(self.data).encode(),
                             "admin", endpoint, "beta", self.directory, YAML))
        with self.assertRaisesRegex(ValueError, "TLS check failed"):
            export.quiet_run([shutil.which("kubectl"), f"--kubeconfig={config}", "--context=admin",
                              "--request-timeout=15s", "get", "--raw=/readyz"], os.environ.copy(),
                             "TLS check failed")


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="cvp-export-controller-")
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CVP_", "ANSIBLE_"))}
        self.marker = self.directory / "sudo-called"
        sudo = self.directory / "sudo"
        sudo.write_text(f"#!/bin/sh\ntouch '{self.marker}'\nexit 99\n")
        sudo.chmod(0o700)
        self.env.update(ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), ANSIBLE_NOCOLOR="1",
                        ANSIBLE_BECOME_EXE=str(sudo), XDG_CONFIG_HOME=str(self.directory / "config"))

    def run_play(self, inventory, playbook, *, success, extra=()):
        result = subprocess.run(["ansible-playbook", "-i", str(inventory), str(playbook), *extra],
                                env=self.env, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertFalse(self.marker.exists(), "controller invoked sudo")
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        return result

    def test_real_slurp_copy_local_fixture_never_templates_remote_yaml_or_escalates_controller(self):
        play = YAML.safe_load((ROOT / "ansible/playbooks/export-kubeconfig.yml").read_bytes())
        tasks = play[0]["tasks"]
        self.assertEqual(tasks[2]["ansible.builtin.slurp"]["src"], "/etc/rancher/k3s/k3s.yaml")
        for task in tasks[1:]:
            self.assertTrue(task["no_log"])
        for task in (tasks[1], tasks[3]):
            self.assertIs(task["vars"]["ansible_become"], False)
        fixture = self.directory / "remote.yaml"
        raw = (SECRET + "\n{{ lookup('pipe', 'false') }}\n").encode()
        fixture.write_bytes(raw)
        stage = self.directory / "stage"
        stage.mkdir(mode=0o700)
        path = stage / "remote.b64"
        export.private_write(path, b"")
        tasks[2]["ansible.builtin.slurp"]["src"] = str(fixture)
        tasks[1]["ansible.builtin.command"]["argv"][2] = str(ROOT / "scripts/cvp_export_kubeconfig.py")
        playbook = self.directory / "fixture.json"
        playbook.write_text(json.dumps(play))
        inventory = self.directory / "hosts.json"
        inventory.write_text(json.dumps({"all": {"vars": {"ansible_become": True}, "children": {
            "k3s_servers": {"hosts": {"beta": {"ansible_connection": "local", "ansible_become": False,
                                                "node_name": "beta", "k3s_role": "server"}}}}}}))
        self.env.update(CVP_KUBECONFIG_HOST="beta", CVP_KUBECONFIG_CONFIRM="beta",
                        CVP_KUBECONFIG_STAGING_FILE=str(path), ANSIBLE_LOCAL_TEMP=str(stage / "ansible-local"))
        self.run_play(inventory, playbook, success=True, extra=("--limit", "beta"))
        self.assertEqual(base64.b64decode(export.private_bytes(path)), raw)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def topology_inventory(self):
        shared = YAML.safe_load((ROOT / "ansible/defaults/group_vars/all.yml").read_bytes())
        shared.update(ansible_become=True, ansible_host="must-not-contact.invalid",
                      ansible_connection="ssh", k3s_server_host="alpha", k3s_cluster_init_host="alpha")
        hosts = {}
        for index, name in enumerate(("alpha", "beta"), 1):
            hosts[name] = {"node_name": name, "k3s_role": "server" if index == 1 else "agent",
                            "k3s_server_init": index == 1, "wireguard_peers_group": "wireguard",
                            "wireguard_address": f"10.77.0.{index}",
                            "wireguard_public_key": base64.b64encode(bytes([index]) * 32).decode(),
                            "k3s_node_labels": ["cvp.io/ingress=true", "svccontroller.k3s.cattle.io/enablelb=true",
                                                "svccontroller.k3s.cattle.io/lbpool=public"] if index == 1 else []}
        return {"all": {"vars": shared, "children": {
            "wireguard": {"hosts": hosts}, "k3s_servers": {"hosts": {"alpha": {}}},
            "k3s_agents": {"hosts": {"beta": {}}}, "ingress": {"hosts": {"alpha": {}}}}}}

    def test_validate_inventory_is_controller_only_loads_operator_and_checks_all_hosts(self):
        inventory = self.directory / "hosts.json"
        data = self.topology_inventory()
        inventory.write_text(json.dumps(data))
        operator = self.directory / "operator.yml"
        operator.write_text(json.dumps({"cvp_operator_hosts": {"beta": {"storage_enabled": False}}}))
        self.env["CVP_OPERATOR_CONFIG_FILE"] = str(operator)
        playbook = ROOT / "ansible/playbooks/validate-inventory.yml"
        self.run_play(inventory, playbook, success=True)
        data["all"]["children"]["wireguard"]["hosts"]["beta"]["k3s_node_labels"] = ["outside.example/key=value"]
        inventory.write_text(json.dumps(data))
        self.run_play(inventory, playbook, success=False, extra=("--limit", "alpha", "--check"))
        data["all"]["children"]["wireguard"]["hosts"]["beta"]["node_name"] = "wrong"
        inventory.write_text(json.dumps(data))
        self.run_play(inventory, playbook, success=False)

    def test_default_empty_inventory_fails_clearly(self):
        inventory = self.directory / "empty-inventory.json"
        inventory.write_text(json.dumps({"all": {"children": {
            group: {"hosts": {}} for group in ("wireguard", "k3s_servers", "k3s_agents", "ingress")}}}))
        result = self.run_play(inventory,
                               ROOT / "ansible/playbooks/validate-inventory.yml", success=False)
        self.assertIn("Inventory is unconfigured", result.stdout)

    def test_suite_passes_with_configured_repository_inventory(self):
        snapshot = self.directory / "snapshot"
        files = (
            "scripts/export-kubeconfig", "scripts/cvp_export_kubeconfig.py",
            "scripts/cvp_wrapper_common.py", "scripts/cvp-topology.py",
            "scripts/test-kubeconfig-export.py", "ansible/ansible.cfg",
            "ansible/defaults/group_vars/all.yml", "ansible/defaults/inventory.yml",
            "ansible/playbooks/export-kubeconfig.yml",
            "ansible/playbooks/validate-inventory.yml", "ansible/playbooks/load-operator-config.yml",
            "ansible/playbooks/tasks/validate-topology.yml", "ansible/playbooks/tasks/validate-node-tags.yml",
        )
        for name in files:
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        inventory = snapshot / "examples/instance/inventory/hosts.yml"
        inventory.parent.mkdir(parents=True)
        inventory.write_text(YAML.safe_dump(self.topology_inventory()))
        self.run_play(inventory, snapshot / "ansible/playbooks/validate-inventory.yml", success=True)
        selected = ["ExportTests", *(
            f"ControllerTests.{name}" for name in unittest.defaultTestLoader.getTestCaseNames(ControllerTests)
            if name != self._testMethodName)]
        result = subprocess.run(["python3", "-B", str(snapshot / "scripts/test-kubeconfig-export.py"),
                                 *selected, "-v"], cwd=snapshot, env=self.env,
                                text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        count = unittest.defaultTestLoader.loadTestsFromTestCase(ExportTests).countTestCases() + len(selected) - 1
        self.assertIn(f"Ran {count} tests", result.stderr)
        self.assertFalse(self.marker.exists(), "snapshot suite invoked sudo")
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_staging_guard_rejects_symlinks_repo_files_and_weak_modes(self):
        stage = self.directory / "stage"
        stage.mkdir(mode=0o700)
        path = stage / "remote.b64"
        export.private_write(path, b"")
        alias = stage / "alias"
        alias.symlink_to(path)
        helper = ROOT / "scripts/cvp_export_kubeconfig.py"
        for candidate, mode in ((alias, 0o600), (helper, 0o600), (path, 0o644)):
            path.chmod(mode)
            env = dict(self.env, CVP_KUBECONFIG_STAGING_FILE=str(candidate))
            result = subprocess.run(["python3", "-B", str(helper), "check-staging"],
                                    env=env, text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
        path.chmod(0o600)
        stage.chmod(0o755)
        result = subprocess.run(["python3", "-B", str(helper), "check-staging"],
                                env=dict(self.env, CVP_KUBECONFIG_STAGING_FILE=str(path)),
                                text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
