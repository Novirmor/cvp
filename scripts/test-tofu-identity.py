#!/usr/bin/env python3
"""Exercise the production identity guard using only local terraform_data."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
from typing import cast
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def block(text, header):
    lines = text[text.index(header):].splitlines()
    depth = 0
    result = []
    for line in lines:
        result.append(line)
        depth += line.count("{") - line.count("}")
        if depth == 0:
            return "\n".join(result)
    raise AssertionError("unterminated HCL block")


def main():
    variables = (ROOT / "tofu/tailscale/variables.tf").read_text()
    resources = (ROOT / "tofu/tailscale/resources.tf").read_text()
    configuration = block(variables, 'variable "tailnet"') + "\n"
    configuration += block(resources, 'resource "terraform_data" "tailnet_identity"') + "\n"
    for kind, name in (("tailscale_acl", "policy"), ("tailscale_dns_configuration", "tailnet")):
        resource = block(resources, f'resource "{kind}" "{name}"')
        dependency = re.search(r"depends_on\s*=\s*(\[[^]]+\])", resource)
        assert dependency, f"{kind}.{name} must depend on the identity guard"
        configuration += f'resource "terraform_data" "{name}" {{\n depends_on = {dependency[1]}\n input = var.tailnet\n}}\n'
    env = {key: value for key, value in os.environ.items() if not key.startswith(("TF_", "AWS_", "CVP_"))}
    with tempfile.TemporaryDirectory(prefix="cvp-identity-test-") as directory:
        (Path(directory) / "main.tf").write_text(configuration)

        def run(*args, success=True, contains=None):
            result = subprocess.run(
                ["tofu", f"-chdir={directory}", *args], env=env,
                text=True, capture_output=True,
            )
            output = result.stdout + result.stderr
            assert (result.returncode == 0) == success, output
            if contains:
                assert contains in output, output

        run("init", "-backend=false", "-input=false", "-no-color")
        run("plan", "-input=false", "-no-color", "-var=tailnet=-", success=False, contains="credential-relative")
        run("apply", "-auto-approve", "-input=false", "-no-color", "-var=tailnet=fixture-a.invalid")
        for name in ("policy", "tailnet"):
            run("plan", "-input=false", "-no-color", "-var=tailnet=fixture-b.invalid",
                f"-target=terraform_data.{name}", success=False, contains="prevent_destroy")

        sandbox = Path(directory) / "sandbox"
        scripts = sandbox / "scripts"
        scripts.mkdir(parents=True)
        for name in ("tofu-operation", "cvp_tofu_operation.py", "cvp_wrapper_common.py"):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        module = sandbox / "tofu/cloudflare"
        module.mkdir(parents=True)
        local_backend = ('terraform {\n backend "local" {\n'
                         f'path = {json.dumps(str(Path(directory) / "state"))}\n'
                         f'workspace_dir = {json.dumps(str(Path(directory) / "workspaces"))}\n'
                         '}\n}\n')
        (module / "main.tf").write_text(
            local_backend +
            'resource "terraform_data" "fixture" { input = "local-only" }\n'
        )
        env["CVP_TOFU_RECOVERY_DIR"] = str(Path(directory) / "recovery")
        initialized = subprocess.run(
            ["tofu", f"-chdir={module}", "init", "-input=false", "-no-color"],
            env=env, text=True, capture_output=True,
        )
        assert initialized.returncode == 0, initialized.stdout + initialized.stderr
        artifacts = Path(directory) / "artifacts"
        artifacts.mkdir(mode=0o700)
        plan = artifacts / "reviewed.tfplan"
        for operation, args in (
            ("plan", [f"-out={plan}"]), ("show", [str(plan)]),
            ("apply", [str(plan)]), ("state-pull", [str(artifacts / "state")]),
        ):
            result = subprocess.run(
                ["bash", str(scripts / "tofu-operation"), "cloudflare", operation, *args],
                cwd=directory, env=env, text=True, capture_output=True,
            )
            assert result.returncode == 0, result.stdout + result.stderr
        for artifact in artifacts.iterdir():
            assert artifact.stat().st_mode & 0o777 == 0o600, artifact
        tailnet = sandbox / "tofu/tailscale"
        tailnet.mkdir()
        (tailnet / "main.tf").write_text(local_backend.replace('/state"', '/tailnet-state"') + configuration)
        result = subprocess.run(["tofu", f"-chdir={tailnet}", "init", "-input=false"],
                                env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr

        def guarded(*args, success=True):
            result = subprocess.run(["bash", str(scripts / "tofu-operation"), "tailscale", *args],
                                    env=env, capture_output=True, text=True)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            return result

        guarded("import", "-var=tailnet=fixture-a.invalid", "terraform_data.policy", "acl", success=False)
        guarded("establish-identity", "fixture-a.invalid")
        state = subprocess.run(["tofu", f"-chdir={tailnet}", "state", "list"], env=env, capture_output=True, text=True)
        assert state.stdout.strip() == "terraform_data.tailnet_identity", state.stdout
        guarded("import", "-var=tailnet=fixture-b.invalid", "terraform_data.policy", "acl", success=False)
        guarded("import", "-var=tailnet=fixture-a.invalid", "terraform_data.policy", "acl")
        guarded("establish-identity", "fixture-b.invalid", success=False)
        guarded("plan", "-var=tailnet=fixture-b.invalid", f"-out={artifacts / 'wrong-tailnet'}", success=False)
        guarded("plan", "-var=tailnet=fixture-a.invalid", f"-out={artifacts / 'right-tailnet'}")
        for workspace in ("legacy", "unexpected"):
            result = subprocess.run(["tofu", f"-chdir={tailnet}", "workspace", "new", workspace],
                                    env=env, text=True, capture_output=True)
            assert result.returncode == 0, result.stdout + result.stderr
            if workspace == "legacy":
                result = subprocess.run(["tofu", f"-chdir={tailnet}", "import", "-input=false",
                                         "-var=tailnet=fixture-a.invalid", "terraform_data.policy", "acl"],
                                        env=env, text=True, capture_output=True)
                assert result.returncode == 0, result.stdout + result.stderr
                guarded("establish-identity", "fixture-b.invalid", success=False)
                guarded("import", "-var=tailnet=fixture-a.invalid", "terraform_data.tailnet", "dns_configuration", success=False)
            else:
                source = (tailnet / "main.tf").read_text()
                (tailnet / "main.tf").write_text(source.replace(
                    'resource "terraform_data" "tailnet_identity" {',
                    'resource "terraform_data" "tailnet_identity" {\n depends_on = [terraform_data.unexpected]\n')
                    + '\nresource "terraform_data" "unexpected" { input = "must not apply" }\n')
                guarded("establish-identity", "fixture-a.invalid", success=False)
                state = subprocess.run(["tofu", f"-chdir={tailnet}", "show", "-json"], env=env, capture_output=True, text=True)
                assert not json.loads(state.stdout).get("values"), state.stdout
        loopback_regressions(Path(directory), scripts, env)
    print("identity guard and bound plan/show/apply/state passed (builtin local resources only)")


class S3Server(ThreadingHTTPServer):
    objects: dict
    calls: list
    fail_state: bool


class S3Fixture(BaseHTTPRequestHandler):
    @property
    def fixture(self):
        return cast(S3Server, self.server)

    def log_message(self, format, *args):
        pass

    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"fixture"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self.fixture.calls.append(("GET", self.path))
        if "list-type=2" in self.path:
            self.reply(200, b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>')
        else:
            value = self.fixture.objects.get(urlsplit(self.path).path)
            self.reply(200 if value is not None else 404, value or b'<Error><Code>NoSuchKey</Code></Error>')

    def do_HEAD(self):
        self.fixture.calls.append(("HEAD", self.path))
        self.reply(200 if urlsplit(self.path).path in self.fixture.objects else 404)

    def do_PUT(self):
        self.fixture.calls.append(("PUT", self.path))
        data = self.rfile.read(int(self.headers["Content-Length"]))
        if self.fixture.fail_state and urlsplit(self.path).path.endswith(".tfstate"):
            self.reply(403, b'<Error><Code>AccessDenied</Code><Message>fixture write failure</Message></Error>')
        else:
            self.fixture.objects[urlsplit(self.path).path] = data
            self.reply(200)

    def do_DELETE(self):
        self.fixture.calls.append(("DELETE", self.path))
        self.fixture.objects.pop(urlsplit(self.path).path, None)
        self.reply(204)


def loopback_regressions(directory, scripts, base_env):
    server = S3Server(("127.0.0.1", 0), S3Fixture)
    server.objects, server.calls, server.fail_state = {}, [], False
    threading.Thread(target=server.serve_forever, daemon=True).start()
    module = scripts.parent / "tofu/cloudflare"
    recovery = directory / "s3-recovery"
    env = dict(base_env, TF_DATA_DIR=str(directory / "s3-cache"), CVP_TOFU_RECOVERY_DIR=str(recovery),
               AWS_ACCESS_KEY_ID="fixture", AWS_SECRET_ACCESS_KEY="fixture", AWS_EC2_METADATA_DISABLED="true",
               AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull, NO_PROXY="127.0.0.1")
    endpoint = f"http://127.0.0.1:{server.server_port}"
    (module / "main.tf").write_text('''terraform {
 backend "s3" {
  bucket = "fixture"
  key = "fixture.tfstate"
  region = "us-east-1"
  use_path_style = true
  use_lockfile = true
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  skip_requesting_account_id = true
  skip_s3_checksum = true
  max_retries = 0
  endpoints = { s3 = "''' + endpoint + '''" }
 }
}
resource "terraform_data" "fixture" { input = sensitive("PRIVATE-STATE-SENTINEL") }
''')
    try:
        result = subprocess.run(["tofu", f"-chdir={module}", "init", "-input=false"], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        del env["AWS_CONFIG_FILE"], env["AWS_SHARED_CREDENTIALS_FILE"]

        def run(*args, extra=None):
            return subprocess.run(["bash", str(scripts / "tofu-operation"), "cloudflare", *args],
                                  env=dict(env, **(extra or {})), capture_output=True, text=True)

        plan = directory / "s3-plan"
        result = run("plan", f"-out={plan}")
        assert result.returncode == 0, result.stdout + result.stderr
        before = len(server.calls)
        for key in ("AWS_ENDPOINT_URL_S3", "AWS_CONFIG_FILE", "TF_LOG_PATH"):
            result = run("apply", str(plan), extra={key: endpoint})
            assert result.returncode != 0 and len(server.calls) == before, result.stdout + result.stderr

        server.fail_state = True
        victim = directory / "public-victim"
        victim.write_text("preserve")
        victim.chmod(0o644)
        fallback = module / "errored.tfstate"
        fallback.symlink_to(victim)
        result = run("apply", str(plan))
        assert result.returncode != 0, result.stdout + result.stderr
        assert "PRIVATE-STATE-SENTINEL" not in result.stdout + result.stderr
        assert victim.read_text() == "preserve" and victim.stat().st_mode & 0o777 == 0o644
        retained = list(recovery.iterdir())
        assert len(retained) == 1, retained
        run_dir = retained[0]
        assert run_dir.stat().st_mode & 0o777 == 0o700
        assert "PRIVATE-STATE-SENTINEL" in (run_dir / "errored.tfstate").read_text()
        assert (run_dir / "input.tfplan").read_bytes() == plan.read_bytes()
        for path in run_dir.iterdir():
            assert path.stat().st_mode & 0o777 == 0o600, path

        fallback.unlink()
        fallback.write_text('{"version":4,"serial":0,"lineage":"old","outputs":{},"resources":[]}')
        fallback.chmod(0o644)
        old_state = fallback.read_bytes()
        result = run("apply", str(plan))
        assert result.returncode != 0 and "PRIVATE-STATE-SENTINEL" not in result.stdout + result.stderr
        assert fallback.read_bytes() == old_state and fallback.stat().st_mode & 0o777 == 0o644

        # Inject a recovery collision only inside the disposable execution directory.
        shim = directory / "tofu-shim"
        shim.mkdir()
        real_tofu = shutil.which("tofu")
        (shim / "tofu").write_text(
            '#!/usr/bin/env python3\nimport os, pathlib, sys\n'
            'if sys.argv[2] == "apply": pathlib.Path(sys.argv[1].split("=",1)[1], "errored.tfstate").write_text("invalid")\n'
            f'os.execv({real_tofu!r}, [{real_tofu!r}, *sys.argv[1:]])\n')
        (shim / "tofu").chmod(0o700)
        before_runs = set(recovery.iterdir())
        result = run("apply", str(plan), extra={"PATH": str(shim) + os.pathsep + env["PATH"]})
        assert result.returncode != 0 and "PRIVATE-STATE-SENTINEL" not in result.stdout + result.stderr
        added, = set(recovery.iterdir()) - before_runs
        assert "PRIVATE-STATE-SENTINEL" in (added / "stderr.log").read_text()
        assert (added / "stderr.log").stat().st_mode & 0o777 == 0o600
        recovery.chmod(0o777)
        before = len(server.calls)
        result = run("apply", str(plan))
        assert result.returncode != 0 and len(server.calls) == before
        recovery.chmod(0o700)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
