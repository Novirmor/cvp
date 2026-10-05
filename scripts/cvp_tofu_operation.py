"""Guarded OpenTofu dispatch and private, bound plan artifacts."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

from cvp_wrapper_common import ROOT, external_path, private_bytes, trusted_parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def arguments(args, *, plan, positionals=2):
    output = None
    forwarded = []
    positional = []
    values = {"var", "var-file", "lock-timeout"}
    booleans = {"no-color", "compact-warnings"}
    if plan:
        values |= {"parallelism"}
        booleans |= {"detailed-exitcode", "concise"}
    index = 0
    while index < len(args):
        argument = args[index]
        index += 1
        if not argument.startswith("-"):
            positional.append(argument)
            continue
        name, separator, value = argument.lstrip("-").partition("=")
        if name in values or (plan and name == "out"):
            if not separator:
                if index == len(args) or args[index].startswith("-"):
                    raise ValueError(f"-{name} requires a value")
                value = args[index]
                index += 1
            if not value:
                raise ValueError(f"-{name} requires a nonempty value")
            if name == "out":
                if output is not None:
                    raise ValueError("provide exactly one -out path")
                output = external_path(value, output=True)
            else:
                if name == "var-file":
                    value = str(external_path(value))
                forwarded.append(f"-{name}={value}")
        elif name in booleans and (not separator or value in ("true", "false")):
            forwarded.append(f"-{name}" + (f"={value}" if separator else ""))
        else:
            raise ValueError(f"unsupported option: -{name}; targeting and mode overrides are forbidden")
    if plan and (output is None or positional):
        raise ValueError("plan requires -out=/absolute/external/path and no positional arguments")
    if not plan and len(positional) != positionals:
        raise ValueError(f"operation requires {positionals} positional arguments")
    return output, forwarded + positional


def data_directory(root):
    data_dir = Path(os.environ.get("TF_DATA_DIR", str(root / ".terraform")))
    if not data_dir.is_absolute():
        data_dir = root / data_dir
    return data_dir.resolve()


def backend_configuration(root):
    try:
        backend = json.loads((data_directory(root) / "terraform.tfstate").read_bytes())["backend"]
    except (OSError, ValueError, KeyError) as error:
        raise ValueError("initialize this root's backend before creating or using a bound plan") from error
    config = backend.get("config", {})
    if backend.get("type") == "s3":
        if not config.get("region"):
            raise ValueError("configure the S3 region explicitly in the backend")
        if any(config.get(key) for key in ("profile", "shared_config_files", "shared_credentials_files", "shared_credentials_file")):
            raise ValueError("shared AWS configuration and profiles are forbidden; use environment or workload credentials")
        if any(config.get(key) for key in ("access_key", "secret_key", "token")):
            raise ValueError("backend files must not contain credentials; use environment or workload credentials")
    elif backend.get("type") == "local":
        for key in ("path", "workspace_dir"):
            value = config.get(key)
            if not value or not Path(value).is_absolute():
                raise ValueError("local test backends require explicit absolute external path and workspace_dir")
            path = Path(value).resolve()
            if path == ROOT or ROOT in path.parents:
                raise ValueError("local state must be outside the repository")
    else:
        raise ValueError("guarded operations support only S3 and explicit external local backends")
    return backend


def binding(root):
    backend = backend_configuration(root)
    data_dir = data_directory(root)
    workspace = os.environ.get("TF_WORKSPACE")
    if not workspace:
        selection = data_dir / "environment"
        workspace = selection.read_text().strip() if selection.exists() else "default"
    return {
        "format": 2,
        "root": str(root),
        "workspace": workspace,
        "backend_sha256": digest(json.dumps(backend, sort_keys=True).encode()),
    }


def guarded_environment(root):
    for key, value in os.environ.items():
        if value and (key.startswith(("TF_CLI_ARGS", "TF_LOG", "TOFU_LOG"))
                      or (key.startswith("AWS_") and "ENDPOINT" in key)
                      or key in {"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"}):
            raise ValueError(f"unset {key}; ambient command, logging, endpoint, and shared AWS overrides are forbidden")
    env = dict(os.environ, TF_DATA_DIR=str(data_directory(root)),
               AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull)
    return env


def recovery_directory():
    value = os.environ.get("CVP_TOFU_RECOVERY_DIR")
    path = Path(value) if value else Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "cvp/tofu"
    if not path.is_absolute() or any(ord(c) < 32 for c in str(path)) or path.is_symlink():
        raise ValueError("recovery directory must be an absolute, non-symlink external path")
    path = path.resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError("recovery directory must be outside the repository")
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    trusted_parent(parent / "recovery")
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    trusted_parent(path / "recovery")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("recovery directory must be owned by you with mode 0700")
    return path


def detailed_exitcode(args):
    enabled = False
    for arg in args:
        if arg in {"-detailed-exitcode", "-detailed-exitcode=true", "-detailed-exitcode=false"}:
            enabled = arg != "-detailed-exitcode=false"
    return enabled


def tofu(root, *args, capture_output=False, stdout=None, input=None):
    env = guarded_environment(root)
    backend_configuration(root)
    directory = Path(tempfile.mkdtemp(prefix=f"{root.name}-{args[0]}-", dir=recovery_directory()))
    succeeded = False
    try:
        for source in root.iterdir():
            if source.name.endswith((".tf", ".tf.json", ".tfvars", ".tfvars.json")) or source.name == ".terraform.lock.hcl":
                if not source.is_file():
                    raise ValueError("OpenTofu configuration inputs must be regular files")
                destination = directory / source.name
                destination.write_bytes(source.read_bytes())
                destination.chmod(0o600)
        (directory / "operation.json").write_text(json.dumps({"root": str(root), "operation": args[0]}))
        if args[0] == "apply":
            saved_plan = directory / "input.tfplan"
            saved_plan.write_bytes(Path(args[-1]).read_bytes())
            args = (*args[:-1], str(saved_plan))
        with (directory / "stdout.log").open("xb") as out, (directory / "stderr.log").open("xb") as err:
            result = subprocess.run(["tofu", f"-chdir={directory}", *args], cwd=directory,
                                    env=env, input=input, stdout=out, stderr=err)
        output = (directory / "stdout.log").read_bytes()
        errors = (directory / "stderr.log").read_bytes()
        succeeded = result.returncode == 0 or (args[0] == "plan" and result.returncode == 2 and detailed_exitcode(args))
        if succeeded and not capture_output:
            if stdout is not None:
                stdout.write(output)
            else:
                sys.stdout.buffer.write(output)
                sys.stdout.buffer.flush()
        return subprocess.CompletedProcess(result.args, result.returncode, output if capture_output else None,
                                           errors if capture_output else None)
    finally:
        if succeeded:
            shutil.rmtree(directory)
        else:
            print(f"OpenTofu did not complete safely. Private logs and recovery state retained at: {directory}", file=sys.stderr)


def bound_tailnet(root):
    result = tofu(root, "state", "pull", capture_output=True)
    if result.returncode:
        raise ValueError("establish the tailnet identity before importing or planning")
    try:
        resources = json.loads(result.stdout).get("resources", [])
        guards = [r for r in resources if r.get("type") == "terraform_data" and r.get("name") == "tailnet_identity" and not r.get("module")]
        instances = guards[0]["instances"] if len(guards) == 1 else []
        if len(instances) != 1 or instances[0].get("deposed"):
            raise ValueError()
        attributes = instances[0]["attributes"]
        tailnet = attributes["input"]["value"]
        if not isinstance(tailnet, str) or not tailnet or tailnet == "-" or attributes["triggers_replace"]["value"] != [tailnet]:
            raise ValueError()
    except (ValueError, KeyError, TypeError, IndexError) as error:
        raise ValueError("missing or invalid durable tailnet identity; use the reviewed establish-identity workflow") from error
    return tailnet


def check_identity(root, forwarded):
    if root.name != "tailscale":
        return
    expected = bound_tailnet(root)
    variables = [arg for arg in forwarded if arg.startswith(("-var=", "-var-file="))]
    result = tofu(root, "console", "-no-color", *variables, input=b"jsonencode(var.tailnet)\n", capture_output=True)
    try:
        selected = json.loads(json.loads(result.stdout)) if result.returncode == 0 else None
    except (ValueError, TypeError):
        selected = None
    if selected != expected:
        raise ValueError("selected tailnet does not match the durable backend/workspace identity")
    return expected


def check_adoption(root, plan):
    if root.name != "tailscale":
        return
    result = tofu(root, "show", "-json", str(plan), capture_output=True)
    if result.returncode:
        raise ValueError("could not inspect the Tailscale plan for singleton adoption")
    try:
        inspected = json.loads(result.stdout)
        changes = inspected.get("resource_changes", [])
        tailnet = inspected["variables"]["tailnet"]["value"]
        resources = inspected["prior_state"]["values"]["root_module"]["resources"]
        guards = [r["values"] for r in resources if r["address"] == "terraform_data.tailnet_identity"]
        if len(guards) != 1 or guards[0].get("input") != tailnet or guards[0].get("triggers_replace") != [tailnet]:
            raise ValueError("plan has no matching established tailnet identity")
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid plan inspection output") from error
    for change in changes:
        if change.get("address") == "terraform_data.tailnet_identity" and change.get("change", {}).get("actions") != ["no-op"]:
            raise ValueError("normal operations must preserve the established tailnet identity")
        if change.get("type") in {"tailscale_acl", "tailscale_dns_configuration"}:
            if "create" in change.get("change", {}).get("actions", []):
                raise ValueError("import the existing Tailscale ACL and DNS configuration before planning changes")


def publish(source, destination):
    os.chmod(source, 0o600)
    with source.open("rb") as stream:
        os.fsync(stream.fileno())
    # link is an atomic no-clobber publication; an existing file or symlink wins.
    os.link(source, destination, follow_symlinks=False)


@contextmanager
def staging(destination):
    trusted_parent(destination)
    with tempfile.TemporaryDirectory(prefix=".cvp-artifact-", dir=destination.parent) as directory:
        fd, name = tempfile.mkstemp(dir=directory)
        os.close(fd)
        yield Path(name)


def plan_operation(root, operation, args):
    destination, forwarded = arguments(args, plan=True)
    manifest = external_path(str(destination) + ".cvp.json", output=True)
    context = binding(root)
    tailnet = check_identity(root, forwarded)
    if tailnet:
        forwarded.append(f"-var=tailnet={tailnet}")
    with staging(destination) as temporary:
        mode = ["-refresh-only"] if operation == "drift-plan" else []
        result = tofu(root, "plan", "-input=false", *mode, *forwarded, f"-out={temporary}")
        detailed = detailed_exitcode(forwarded)
        if result.returncode != 0 and not (result.returncode == 2 and detailed):
            return result.returncode
        if not temporary.stat().st_size:
            raise ValueError("OpenTofu did not produce a plan artifact")
        check_adoption(root, temporary)
        if binding(root) != context:
            raise ValueError("backend/workspace changed while planning")
        context["plan_sha256"] = digest(temporary.read_bytes())
        context["operation"] = operation
        with staging(manifest) as metadata:
            metadata.write_text(json.dumps(context, sort_keys=True) + "\n")
            publish(metadata, manifest)
            try:
                publish(temporary, destination)
            except BaseException:
                manifest.unlink()
                raise
        print(f"Saved bound plan: {destination}")
        return result.returncode


def use_plan(root, operation, args):
    if len(args) != 1:
        raise ValueError(f"{operation} requires exactly one bound plan artifact")
    source = external_path(args[0])
    trusted_parent(source)
    manifest = external_path(str(source) + ".cvp.json")
    data = private_bytes(source)
    metadata = json.loads(private_bytes(manifest))
    expected = binding(root)
    if (
        not isinstance(metadata, dict)
        or any(metadata.get(key) != value for key, value in expected.items())
        or metadata.get("plan_sha256") != digest(data)
    ):
        raise ValueError("plan hash, root, backend, or workspace does not match; generate and review a new plan")
    with staging(source) as temporary:
        temporary.write_bytes(data)
        check_adoption(root, temporary)
        flags = ["-no-color"] if operation == "show" else ["-input=false"]
        return tofu(root, operation, *flags, str(temporary)).returncode


def establish_identity(root, args):
    if root.name != "tailscale":
        raise ValueError("establish-identity is a Tailscale-only operation")
    _, forwarded = arguments(args, plan=False, positionals=1)
    tailnet = forwarded.pop()
    if not tailnet or tailnet == "-" or tailnet != tailnet.strip() or any(ord(c) < 32 for c in tailnet):
        raise ValueError("provide one explicit tailnet ID/domain")
    context = binding(root)
    existing = tofu(root, "show", "-json", capture_output=True)
    existing_root = json.loads(existing.stdout).get("values", {}).get("root_module", {}) if existing.returncode == 0 else None
    if existing_root is None or existing_root.get("resources") or existing_root.get("child_modules"):
        raise ValueError("establish-identity requires empty state; existing/imported state needs a reviewed migration")
    directory = recovery_directory()
    with staging(directory / "identity-plan") as plan:
        result = tofu(root, "plan", "-input=false", "-refresh=false", *forwarded,
                      f"-var=tailnet={tailnet}", "-target=terraform_data.tailnet_identity", f"-out={plan}")
        if result.returncode:
            return result.returncode
        result = tofu(root, "show", "-json", str(plan), capture_output=True)
        if result.returncode:
            raise ValueError("could not inspect identity establishment plan")
        inspected = json.loads(result.stdout)
        changes = inspected.get("resource_changes", [])
        prior = inspected.get("prior_state", {}).get("values", {}).get("root_module", {})
        if prior.get("resources") or prior.get("child_modules") or len(changes) != 1:
            raise ValueError("identity establishment must create only the guard in empty state")
        change = changes[0]
        after = change.get("change", {}).get("after", {})
        if (change.get("address") != "terraform_data.tailnet_identity"
                or change.get("provider_name") != "terraform.io/builtin/terraform"
                or change.get("change", {}).get("actions") != ["create"]
                or after.get("input") != tailnet or after.get("triggers_replace") != [tailnet]
                or binding(root) != context):
            raise ValueError("unsafe identity establishment plan")
        result = tofu(root, "apply", "-input=false", str(plan))
        if result.returncode == 0 and bound_tailnet(root) != tailnet:
            raise ValueError("identity establishment did not persist the expected tailnet")
        return result.returncode


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in {"cloudflare", "tailscale"}:
        raise ValueError("usage: tofu-operation <cloudflare|tailscale> <plan|drift-plan|apply|show|import|establish-identity|state-list|state-pull> [arguments]")
    os.umask(0o077)
    root = ROOT / "tofu" / sys.argv[1]
    guarded_environment(root)
    operation, args = sys.argv[2], sys.argv[3:]
    os.environ["TF_WORKSPACE"] = binding(root)["workspace"]
    if operation in {"plan", "drift-plan"}:
        return plan_operation(root, operation, args)
    if operation in {"show", "apply"}:
        return use_plan(root, operation, args)
    if operation == "import":
        _, forwarded = arguments(args, plan=False)
        context = binding(root)
        tailnet = check_identity(root, forwarded)
        if tailnet:
            forwarded = [*forwarded[:-2], f"-var=tailnet={tailnet}", *forwarded[-2:]]
        if binding(root) != context:
            raise ValueError("backend changed while validating import identity")
        return tofu(root, "import", "-input=false", *forwarded).returncode
    if operation == "establish-identity":
        return establish_identity(root, args)
    if operation == "state-list" and not args:
        return tofu(root, "state", "list").returncode
    if operation == "state-pull" and len(args) == 1:
        destination = external_path(args[0], output=True)
        with staging(destination) as temporary:
            with temporary.open("wb") as output:
                result = tofu(root, "state", "pull", stdout=output)
            if result.returncode:
                return result.returncode
            if not temporary.stat().st_size:
                raise ValueError("OpenTofu returned empty state")
            publish(temporary, destination)
        return 0
    raise ValueError("unknown operation or invalid arguments")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.exit(f"error: {error}")
