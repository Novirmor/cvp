"""Local input validation shared by the operator wrappers."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent


def external_path(value, *, output=False):
    if any(ord(character) < 32 for character in value):
        raise ValueError("paths must not contain control characters")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    if output and path.is_symlink():
        raise ValueError("output must not be a symlink")
    path = path.resolve(strict=not output)
    if path == ROOT or ROOT in path.parents:
        raise ValueError("sensitive files must be outside the repository")
    if output:
        if not path.parent.is_dir():
            raise ValueError("output parent directory must already exist")
        if path.exists():
            raise ValueError("output already exists; choose a new artifact name")
    elif not path.is_file() or not os.access(path, os.R_OK):
        raise ValueError("input must be a readable regular file")
    return path


def trusted_parent(path):
    for directory in (path.parent, *path.parent.parents):
        info = directory.stat()
        if info.st_uid not in (0, os.getuid()):
            raise ValueError("artifact directory ancestry must be owned by you or root")
        if info.st_mode & 0o022:
            # A root-owned sticky ancestor such as /tmp cannot rename our directory.
            if directory == path.parent or not (
                info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            ):
                raise ValueError("use an artifact directory not writable by other users")


def private_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("artifact must be a regular file owned by you with mode 0600")
        return stream.read()


def operator_config(path, *, with_digest=False):
    try:
        import yaml
    except ImportError as error:
        raise ValueError("operator configuration validation requires PyYAML in the controller Python") from error

    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    expected = os.environ.get("CVP_OPERATOR_CONFIG_SHA256")
    if expected and digest != expected:
        raise ValueError("operator configuration changed during onboarding")

    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        loader.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, str) or key in result:
                raise ValueError("operator configuration requires unique string keys")
            result[key] = loader.construct_object(value_node)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        data = yaml.load(raw, Loader=UniqueLoader)
    except (yaml.YAMLError, UnicodeError) as error:
        raise ValueError("invalid operator configuration YAML/JSON") from error
    if not isinstance(data, dict) or set(data) - {"cvp_operator_defaults", "cvp_operator_hosts"}:
        raise ValueError("use cvp_operator_defaults and cvp_operator_hosts, not global extra vars")
    defaults = data.get("cvp_operator_defaults", {})
    hosts = data.get("cvp_operator_hosts", {})
    if not isinstance(defaults, dict) or not isinstance(hosts, dict):
        raise ValueError("operator defaults and hosts must be mappings")
    for host, values in hosts.items():
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
            raise ValueError("operator host keys must be inventory node names")
        validate_operator_values(values, per_host=True)
    validate_operator_values(defaults, per_host=False)
    files = {}
    resolve_operator_values(defaults, files)
    for values in hosts.values():
        resolve_operator_values(values, files)
    # Referenced credential files are pinned separately from the configuration
    # text: a key file replaced mid-operation must stop the run too.
    files_digest = credential_files_digest(files)
    expected_files = os.environ.get("CVP_OPERATOR_FILES_SHA256")
    if expected_files and files_digest != expected_files:
        raise ValueError("a referenced credential file changed during the operation")
    if with_digest == "files":
        return data, digest, files_digest
    return (data, digest) if with_digest else data


def credential_files_digest(files):
    content = b"".join(name.encode() + b"\0" + hashlib.sha256(value).digest()
                       for name, value in sorted(files.items()))
    return hashlib.sha256(content).hexdigest()


def validate_operator_values(values, *, per_host):
    if not isinstance(values, dict):
        raise ValueError("each operator host entry must be a mapping")
    identity = {
        "base_admin_user", "base_ssh_port", "wireguard_address", "wireguard_public_key",
        "wireguard_endpoint", "wireguard_interface", "wireguard_port", "wireguard_peers_group",
        "tailscale_address", "tailscale_login_server",
    }
    host_only = {
        "wireguard_private_key", "wireguard_private_key_file", "tailscale_auth_key",
        "tailscale_advertise_tags", "storage_device", "storage_mountpoint",
        "storage_manage_device", "storage_allow_format",
        "storage_format_confirmation", "wireguard_rotate_private_key",
        "wireguard_rotation_confirm", "k3s_backup_disable_confirm",
    }
    for key in values:
        if (
            key in identity
            or not key.startswith(("base_", "wireguard_", "tailscale_", "firewall_", "storage_", "k3s_backup_"))
            or (not per_host and key in host_only)
            or key in {"tailscale_extra_up_args", "tailscale_extra_set_args"}
        ):
            raise ValueError("connection/identity overrides and global per-node inputs are forbidden")


def credential_file(value, files):
    if not isinstance(value, str):
        raise ValueError("credential file references must name an absolute path")
    path = external_path(value)
    content = private_bytes(path)
    files[str(path)] = content
    try:
        text = content.decode("utf-8")
    except UnicodeError:
        raise ValueError("referenced credential file must be UTF-8 text") from None
    return text[:-1] if text.endswith("\n") else text


def resolve_operator_values(values, files=None):
    credentials = {"wireguard_private_key", "tailscale_auth_key"}
    files = {} if files is None else files

    def literal(value):
        if isinstance(value, str) and any(token in value for token in ("{{", "{%", "{#")):
            raise ValueError("operator configuration is literal data; use {env: NAME} or {file: PATH} for supported credentials")
        if isinstance(value, dict):
            if "env" in value or "file" in value:
                raise ValueError("credential references are allowed only for supported credential fields")
            for child in value.values():
                literal(child)
        elif isinstance(value, list):
            for child in value:
                literal(child)

    for key, value in values.items():
        if key in credentials and isinstance(value, dict):
            if set(value) == {"file"}:
                value = credential_file(value["file"], files)
            elif set(value) == {"env"} and isinstance(value["env"], str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value["env"]):
                value = os.environ.get(value["env"], "")
            else:
                raise ValueError("credential references must have exactly one env key naming an environment variable "
                                 "or one file key naming an absolute private file")
            if not value or any(ord(character) < 32 for character in value):
                raise ValueError("referenced credential is missing, empty, or contains control characters")
            values[key] = value
        if key in credentials and not isinstance(value, str):
            raise ValueError("credentials must be literal strings, {env: NAME}, or {file: PATH} references")
        literal(value)


def ssh_options(user="", identity=""):
    args = "-o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none -o ForwardAgent=no"
    result = {
        "ansible_host_key_checking": True,
        "ansible_ssh_host_key_checking": True,
        "ansible_ssh_args": args,
        "ansible_ssh_common_args": "",
        "ansible_ssh_extra_args": "",
        "ansible_scp_extra_args": "",
        "ansible_sftp_extra_args": "",
    }
    if user:
        if user not in {"root", "ops"}:
            raise ValueError("unsupported access-bootstrap user")
        result.update(ansible_user=user, ansible_ssh_user=user)
    if identity:
        identity = str(external_path(identity))
        result.update(ansible_private_key_file=identity, ansible_ssh_private_key_file=identity,
                      ansible_private_key="", ansible_ssh_private_key="", ansible_ssh_pkcs11_provider="")
        result["ansible_ssh_args"] += (
            " -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none"
            " -o PreferredAuthentications=publickey -o PasswordAuthentication=no"
            " -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no -o HostbasedAuthentication=no"
        )
    return result


def operator_path():
    explicit = os.environ.get("CVP_OPERATOR_CONFIG_FILE", "")
    if os.environ.get("CVP_OPERATOR_CONFIG_ABSENT") == "1":
        if os.environ.get("CVP_OPERATOR_CONFIG_SHA256"):
            raise ValueError("operator configuration cannot be both present-pinned and absent-pinned")
        directory = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        candidate = directory / "cvp/operator.yml"
        if explicit or candidate.exists() or candidate.is_symlink():
            raise ValueError("operator configuration appeared during onboarding")
        return None
    if explicit:
        return external_path(explicit)
    directory = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    candidate = directory / "cvp/operator.yml"
    if candidate.exists() or candidate.is_symlink():
        return external_path(str(candidate))
    if os.environ.get("CVP_OPERATOR_CONFIG_SHA256"):
        raise ValueError("pinned operator configuration is missing")
    return None


def main():
    action = sys.argv[1]
    if action == "ssh-options":
        print(json.dumps(ssh_options(*sys.argv[2:])))
        return
    if action == "ssh-inventory":
        inventory = json.load(sys.stdin)
        for values in inventory.get("_meta", {}).get("hostvars", {}).values():
            if values.get("ansible_connection", "ssh") not in {"ssh", "ansible.builtin.ssh"}:
                raise ValueError("guarded host operations require the SSH connection plugin")
        return
    if action in {"operator-load", "operator-config", "operator-inventory", "operator-digest", "operator-files-digest"}:
        try:
            import yaml
        except ImportError:
            executable = shutil.which("ansible-playbook")
            if not executable or os.environ.get("CVP_OPERATOR_ANSIBLE_PYTHON"):
                raise ValueError("operator configuration requires the pinned Ansible Python environment")
            interpreter = shlex.split(Path(executable).resolve().read_text().splitlines()[0].removeprefix("#!"))
            if not interpreter or not Path(interpreter[0]).is_absolute() or "python" not in Path(interpreter[0]).name:
                raise ValueError("cannot locate the pinned Ansible Python environment")
            os.environ["CVP_OPERATOR_ANSIBLE_PYTHON"] = "1"
            os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])
    if action in ("operator-path", "operator-load"):
        path = operator_path()
        if action == "operator-path":
            print(path or "")
            return
        inventory_hosts = json.load(sys.stdin)
        data = operator_config(path) if path else {}
        assert isinstance(data, dict)
        if set(data.get("cvp_operator_hosts", {})) - set(inventory_hosts):
            raise ValueError("operator configuration names a host absent from inventory")
        print(json.dumps(data))
        return
    value = sys.argv[2]
    path = external_path(value)
    if action in ("operator-config", "operator-inventory", "operator-digest", "operator-files-digest"):
        data, digest, files_digest = operator_config(path, with_digest="files")
        if action == "operator-digest":
            print(digest)
            return
        if action == "operator-files-digest":
            print(files_digest)
            return
        if action == "operator-inventory":
            inventory = json.load(sys.stdin)
            known = inventory.get("_meta", {}).get("hostvars", {})
            if set(data.get("cvp_operator_hosts", {})) - set(known):
                raise ValueError("operator configuration names a host absent from inventory")
            return
    elif action != "external-file":
        raise ValueError("unknown validation action")
    print(path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"error: {error}")
