#!/usr/bin/env python3
import base64
import binascii
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from cvp_wrapper_common import ROOT, external_path, inventory_args, private_bytes, ssh_options, trusted_parent


def yaml_module(script=None):
    try:
        import yaml
        return yaml
    except ImportError:
        executable = shutil.which("ansible-playbook")
        if not executable or os.environ.get("CVP_KUBECONFIG_ANSIBLE_PYTHON"):
            raise ValueError("PyYAML requires the pinned Ansible Python; run through mise exec") from None
        interpreter = shlex.split(Path(executable).resolve().read_text().splitlines()[0].removeprefix("#!"))
        if not interpreter or not Path(interpreter[0]).is_absolute() or "python" not in Path(interpreter[0]).name:
            raise ValueError("cannot locate the pinned Ansible Python")
        os.environ["CVP_KUBECONFIG_ANSIBLE_PYTHON"] = "1"
        os.execv(interpreter[0], [*interpreter, "-B", str(script or Path(__file__).resolve()), *sys.argv[1:]])


def private_address(value):
    address = ipaddress.ip_address(value)
    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
    return any(address in ipaddress.ip_network(network) for network in networks)


def server_url(value):
    if not value or any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("CVP_KUBECONFIG_SERVER must be https://chosen-private-endpoint:6443")
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.port == 6443 and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and not parsed.path and not parsed.query and not parsed.fragment)
    except ValueError:
        raise ValueError("CVP_KUBECONFIG_SERVER must be https://chosen-private-endpoint:6443 without URL extras") from None
    if not valid or any(character in value for character in "{}\\?#@%"):
        raise ValueError("CVP_KUBECONFIG_SERVER must be https://chosen-private-endpoint:6443 without URL extras")
    host = parsed.hostname
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", host):
            raise ValueError("API endpoint must be a private IP or DNS name") from None
        try:
            addresses = [entry[4][0] for entry in socket.getaddrinfo(host, 6443, type=socket.SOCK_STREAM)]
        except OSError:
            raise ValueError("API endpoint DNS failed; connect the private network and check the endpoint") from None
    if not addresses or not all(private_address(address) for address in addresses):
        raise ValueError("API endpoint must resolve only to private mesh addresses, not public or loopback addresses")
    return value


def output_path(value):
    path = external_path(value, output=True)
    original = Path(value)
    if any(part.is_symlink() for part in (original, *original.parents)):
        raise ValueError("output path must not contain symlink aliases")
    trusted_parent(path)
    return path


def staging_path():
    value = os.environ.get("CVP_KUBECONFIG_STAGING_FILE", "")
    path = external_path(value)
    if path != Path(value) or any(part.is_symlink() for part in (Path(value), *Path(value).parents)):
        raise ValueError("staging path must not contain aliases")
    trusted_parent(path)
    info = path.parent.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("staging directory must be owned by you with mode 0700")
    private_bytes(path)
    return path


def inventory_host(data, host):
    def members(group, seen=None):
        seen = set() if seen is None else seen
        if group in seen:
            return set()
        seen.add(group)
        row = data.get(group, {})
        result = set(row.get("hosts", []))
        for child in row.get("children", []):
            result.update(members(child, seen))
        return result

    row = data.get("_meta", {}).get("hostvars", {}).get(host, {})
    if host in data or host not in members("k3s_servers") or host in members("k3s_agents"):
        raise ValueError("CVP_KUBECONFIG_HOST must be exactly one inventory server in k3s_servers, not an agent or group")
    if row.get("node_name") != host or row.get("k3s_role") != "server":
        raise ValueError("selected server must have matching current node_name and k3s_role=server")
    if row.get("ansible_connection", "ssh") not in {"ssh", "ansible.builtin.ssh"}:
        raise ValueError("kubeconfig export requires the SSH connection plugin")


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def transform(raw, context, server, host, directory, yaml):
    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        loader.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, str) or key in result:
                raise ValueError("kubeconfig requires unique string keys")
            result[key] = loader.construct_object(value_node)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        data = yaml.load(raw, Loader=UniqueLoader)
        if not isinstance(data, dict) or data.get("apiVersion") != "v1" or data.get("kind") != "Config":
            raise ValueError()
        entries = []
        for field, payload in (("clusters", "cluster"), ("users", "user"), ("contexts", "context")):
            rows = data[field]
            if not isinstance(rows, list) or len(rows) != 1:
                raise ValueError()
            entry = rows[0]
            if not isinstance(entry["name"], str) or not entry["name"] or not isinstance(entry[payload], dict):
                raise ValueError()
            entries.append(entry)
        cluster_entry, user_entry, context_entry = entries
        if (data["current-context"] != context_entry["name"]
                or context_entry["context"]["cluster"] != cluster_entry["name"]
                or context_entry["context"]["user"] != user_entry["name"]):
            raise ValueError()
        cluster, user = cluster_entry["cluster"], user_entry["user"]
        if "insecure-skip-tls-verify" in cluster:
            raise ValueError()
        embedded = [cluster["certificate-authority-data"], user["client-certificate-data"], user["client-key-data"]]
        decoded = []
        for value in embedded:
            if not isinstance(value, str) or not value:
                raise ValueError()
            decoded.append(base64.b64decode(value, validate=True))
        tls = ssl.create_default_context(cadata=decoded[0].decode("ascii"))
        cert_path, key_path = directory / "client.crt", directory / "client.key"
        try:
            private_write(cert_path, decoded[1])
            private_write(key_path, decoded[2])
            tls.load_cert_chain(cert_path, key_path, password=lambda: b"")
        finally:
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)
    except (KeyError, TypeError, ValueError, RecursionError, yaml.YAMLError, UnicodeError, ssl.SSLError, binascii.Error):
        raise ValueError("remote kubeconfig must contain one linked context with valid embedded CA, client certificate and key; insecure TLS is forbidden") from None
    cluster_name, user_name = f"{context}-cluster", f"{context}-admin"
    result = {
        "apiVersion": "v1", "kind": "Config", "preferences": {},
        "clusters": [{"name": cluster_name, "cluster": {
            "server": server, "certificate-authority-data": embedded[0]}}],
        "users": [{"name": user_name, "user": {
            "client-certificate-data": embedded[1], "client-key-data": embedded[2]}}],
        "contexts": [{"name": context, "context": {"cluster": cluster_name, "user": user_name}}],
        "current-context": context,
        "extensions": [{"name": "cvp-export", "extension": {
            "source-host": host, "credential-scope": "cluster-admin",
            "exported-at": datetime.now(timezone.utc).isoformat()}}],
    }
    return yaml.safe_dump(result, sort_keys=False).encode()


def quiet_run(argv, env, message, *, capture=False):
    try:
        result = subprocess.run(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError(message) from None
    if result.returncode:
        raise ValueError(message)
    return result.stdout


def export(yaml):
    if sys.argv[1:]:
        raise ValueError("export-kubeconfig takes no arguments; use the CVP_KUBECONFIG_* environment contract")
    host = os.environ.get("CVP_KUBECONFIG_HOST", "")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        raise ValueError("set CVP_KUBECONFIG_HOST to one exact lowercase inventory server name")
    if os.environ.get("CVP_KUBECONFIG_CONFIRM") != host:
        raise ValueError("export grants root cluster-admin access; set CVP_KUBECONFIG_CONFIRM to the reviewed server name")
    context = os.environ.get("CVP_KUBECONFIG_CONTEXT", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context):
        raise ValueError("set CVP_KUBECONFIG_CONTEXT to an explicit name using letters, digits, dots, underscores or hyphens")
    server = server_url(os.environ.get("CVP_KUBECONFIG_SERVER", ""))
    output = output_path(os.environ.get("CVP_KUBECONFIG_OUTPUT", ""))
    env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"),
               ANSIBLE_HOST_KEY_CHECKING="True", ANSIBLE_SSH_HOST_KEY_CHECKING="True",
               ANSIBLE_TRANSPORT="ssh", ANSIBLE_LOG_PATH=os.devnull, ANSIBLE_DEBUG="False",
               ANSIBLE_STDOUT_CALLBACK="default", ANSIBLE_CALLBACKS_ENABLED="",
               ANSIBLE_DISPLAY_ARGS_TO_STDOUT="False", ANSIBLE_KEEP_REMOTE_FILES="False")
    try:
        data = json.loads(quiet_run(["ansible-inventory", *inventory_args(), "--list"], env,
                                   "cannot read inventory; install pinned Ansible with mise", capture=True))
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError("Ansible returned invalid inventory data") from None
    inventory_host(data, host)
    options = ssh_options()
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with tempfile.TemporaryDirectory(prefix=".cvp-kubeconfig-", dir=output.parent) as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            staging = directory / "remote.b64"
            private_write(staging, b"")
            env.update(CVP_KUBECONFIG_STAGING_FILE=str(staging), ANSIBLE_LOCAL_TEMP=str(directory / "ansible-local"))
            quiet_run(["ansible-playbook", *inventory_args(),
                       str(ROOT / "ansible/playbooks/export-kubeconfig.yml"), "--limit", host,
                       "-e", json.dumps(options)], env,
                      "could not stage admin kubeconfig; check inventory identity, trusted SSH access, remote sudo and K3s availability")
            try:
                raw = base64.b64decode(private_bytes(staging), validate=True)
            except binascii.Error:
                raise ValueError("Ansible staging did not contain the expected slurped kubeconfig") from None
            kubeconfig = directory / "kubeconfig"
            private_write(kubeconfig, transform(raw, context, server, host, directory, yaml))
            staging.unlink()
            quiet_run(["kubectl", f"--kubeconfig={kubeconfig}", f"--context={context}",
                       "--request-timeout=15s", "get", "--raw=/readyz"], env,
                      "API readiness/TLS check failed; check private-network connectivity, port 6443, server certificate SANs and current admin credentials; no kubeconfig published")
            current, pinned = output.parent.stat(follow_symlinks=False), os.fstat(parent_fd)
            if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise ValueError("output directory changed during export; choose a trusted directory and retry")
            os.link(kubeconfig, output.name, dst_dir_fd=parent_fd, follow_symlinks=False)
            os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    print(f"Exported verified cluster-admin kubeconfig to {output} (mode 0600, context {context}).")


def interrupted(signum, frame):
    raise KeyboardInterrupt()


def main():
    signal.signal(signal.SIGTERM, interrupted)
    if sys.argv[1:] == ["check-staging"]:
        staging_path()
        return
    export(yaml_module())


if __name__ == "__main__":
    try:
        main()
    except FileExistsError:
        sys.exit("error: output already exists; no overwrite is permitted")
    except ValueError as error:
        sys.exit(f"error: {error}")
    except (OSError, KeyboardInterrupt):
        sys.exit("error: export interrupted or private file operation failed; staging cleaned up; retry with a new trusted output path")
