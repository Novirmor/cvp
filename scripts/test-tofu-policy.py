#!/usr/bin/env python3
"""Verify CI access policy rendering without provider credentials or API calls."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "tofu/tailscale"


def policy(env, ci_users):
    values = {
        "tailnet": "test-tailnet.invalid",
        "admin_users": ["admin@example.invalid"],
        "ci_users": ci_users,
        "magic_dns": True,
        "override_local_dns": False,
        "dns_nameservers": [],
    }
    result = subprocess.run(
        ["tofu", f"-chdir={MODULE}", "console", "-no-color",
         *(f"-var={key}={json.dumps(value)}" for key, value in values.items())],
        input="jsonencode(local.policy)\n", text=True, capture_output=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(json.loads(result.stdout))


def main():
    with tempfile.TemporaryDirectory(prefix="cvp-tofu-policy-") as data_dir:
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("TF_", "TOFU_", "AWS_", "TAILSCALE_"))}
        env["TF_DATA_DIR"] = data_dir
        env["TF_VAR_state_passphrase"] = "fixture-high-entropy-passphrase-only-for-tests-0123456789"
        init = subprocess.run(["tofu", f"-chdir={MODULE}", "init",
                               "-backend-config=path=" + str(Path(data_dir) / "state.tfstate"),
                               "-backend-config=workspace_dir=" + str(Path(data_dir) / "workspaces"),
                               "-input=false", "-lockfile=readonly", "-no-color"],
                              capture_output=True, text=True, env=env)
        assert init.returncode == 0, init.stdout + init.stderr
        for ci_users in ([], ["ci@example.invalid"]):
            rendered = policy(env, ci_users)
            assert rendered["groups"]["group:admin"] == ["admin@example.invalid"]
            assert ("group:ci" in rendered["groups"]) == bool(ci_users)
            assert rendered["acls"][1]["src"] == (["group:ci"] if ci_users else []) + ["tag:ci"]
            assert ("group:ci" in [test["src"] for test in rendered["tests"]]) == bool(ci_users)
            assert any(test["src"] == "tag:ci" for test in rendered["tests"])
            assert rendered["tagOwners"]["tag:ci"] == ["group:admin"]
    print("CI group omitted only when empty; tagged CI device guard retained")


if __name__ == "__main__":
    main()
