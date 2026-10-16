#!/usr/bin/env python3
"""Exercise production encryption blocks with local builtin resources only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MARKER = "fixture-secret-never-on-disk"


def run(directory, env, *arguments, ok=True):
    result = subprocess.run(["tofu", f"-chdir={directory}", *arguments],
                            env=env, capture_output=True, text=True)
    assert (result.returncode == 0) == ok, result.stdout + result.stderr
    return result


def main():
    for root in ("cloudflare", "tailscale"):
        with tempfile.TemporaryDirectory(prefix="cvp-encrypted-tofu-") as temporary:
            directory = Path(temporary)
            module = directory / "module"
            module.mkdir()
            shutil.copy2(ROOT / "tofu" / root / "encryption.tf", module / "encryption.tf")
            shutil.copy2(ROOT / "tofu" / root / "backend.tf", module / "backend.tf")
            (module / "main.tf").write_text(
                'resource "terraform_data" "secret" { input = sensitive("' + MARKER + '") }\n')
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("TF_", "TOFU_", "AWS_"))}
            env["TF_DATA_DIR"] = str(directory / "cache")
            env["TF_VAR_state_passphrase"] = "fixture-high-entropy-passphrase-only-for-tests-0123456789"
            state = directory / "state.tfstate"
            plan = directory / "plan.tfplan"
            run(module, env, "init", "-input=false", "-backend-config=path=" + str(state),
                "-backend-config=workspace_dir=" + str(directory / "workspaces"))
            run(module, env, "plan", "-input=false", "-out=" + str(plan))
            assert MARKER.encode() not in plan.read_bytes(), "plan contains secret in plaintext"
            run(module, env, "apply", "-input=false", str(plan))
            envelope = json.loads(state.read_bytes())
            assert "encrypted_data" in envelope and MARKER.encode() not in state.read_bytes()
            backup = directory / "state.tfstate.backup"
            if backup.exists():
                assert MARKER.encode() not in backup.read_bytes()
            missing = dict(env)
            del missing["TF_VAR_state_passphrase"]
            run(module, missing, "plan", "-input=false", ok=False)
            wrong = dict(env, TF_VAR_state_passphrase="wrong-passphrase-with-sufficient-length-0123456789")
            run(module, wrong, "plan", "-input=false", ok=False)
    export_fixture()
    print("both local roots encrypt saved plans and state, and refuse missing/wrong keys")


def export_fixture():
    with tempfile.TemporaryDirectory(prefix="cvp-encrypted-export-") as temporary:
        directory = Path(temporary)
        sandbox = directory / "platform"
        module = sandbox / "tofu/tailscale"
        module.mkdir(parents=True)
        scripts = sandbox / "scripts"
        scripts.mkdir()
        for name in ("tofu-operation", "cvp_tofu_operation.py", "cvp_wrapper_common.py"):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        for name in ("backend.tf", "encryption.tf"):
            shutil.copy2(ROOT / "tofu/tailscale" / name, module / name)
        secret = "tskey-auth-fixture-not-real"
        (module / "main.tf").write_text(
            'resource "terraform_data" "tailnet_identity" {\n'
            '  input = "fixture.invalid"\n'
            '  triggers_replace = ["fixture.invalid"]\n'
            '}\n'
            'output "enrollment_keys" {\n'
            f'  value = {{ eve282 = sensitive("{secret}") }}\n'
            '  sensitive = true\n'
            '}\n')
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("TF_", "TOFU_", "AWS_", "CVP_"))}
        env.update(TF_DATA_DIR=str(directory / "cache"),
                   TF_VAR_state_passphrase="fixture-high-entropy-passphrase-only-for-tests-0123456789",
                   CVP_TOFU_RECOVERY_DIR=str(directory / "recovery"))
        state = directory / "state.tfstate"
        run(module, env, "init", "-input=false", "-backend-config=path=" + str(state),
            "-backend-config=workspace_dir=" + str(directory / "workspaces"))
        run(module, env, "apply", "-auto-approve", "-input=false")
        identity = directory / "operator.agekey"
        generated = subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, text=True)
        assert generated.returncode == 0, generated.stderr
        recipient = subprocess.check_output(["age-keygen", "-y", str(identity)], text=True).strip()
        destination = directory / "eve282.sops.json"
        command = [str(scripts / "tofu-operation"), "tailscale", "export-enrollment-key",
                   "eve282", str(destination), recipient]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert secret not in destination.read_text() + result.stdout + result.stderr
        assert secret.encode() not in state.read_bytes()
        decrypted = subprocess.run(["sops", "--decrypt", str(destination)],
                                   env=dict(env, SOPS_AGE_KEY_FILE=str(identity)),
                                   capture_output=True, text=True)
        assert decrypted.returncode == 0, decrypted.stderr
        assert json.loads(decrypted.stdout) == {"TAILSCALE_AUTH_KEY": secret}
        assert destination.stat().st_mode & 0o777 == 0o600
        assert not any((directory / "recovery").iterdir())
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        assert result.returncode != 0 and secret not in result.stdout + result.stderr


if __name__ == "__main__":
    main()
