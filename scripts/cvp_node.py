#!/usr/bin/env python3
"""Operator node lifecycle: scaffold a node, bootstrap a fresh Debian host, join it.

new        Write inventory, host vars, a WireGuard key, and the operator entry for
           one node as a single validated transaction. Never contacts a host.
bootstrap  Trust a fresh Debian host's SSH key by its provider fingerprint, copy
           scripts/node-bootstrap.sh to it, and run it as root to create the
           `ops` operator. Root may log in with a password once.
join       Run the guarded join stages in order and record progress, so a rerun
           resumes after the last completed stage. An interrupted mutating stage
           is never retried without --retry-reviewed.

SSH always uses the node's public address. Tailscale is for people reaching
internal services; WireGuard is node-to-node cluster traffic only.
"""

import argparse
import base64
import difflib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    executable = shutil.which("ansible-playbook")
    if not executable or os.environ.get("CVP_NODE_ANSIBLE_PYTHON"):
        sys.exit("error: cvp_node requires the pinned Ansible Python environment (run through task)")
    interpreter = shlex.split(Path(executable).resolve().read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_NODE_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cvp_wrapper_common as common  # noqa: E402

ROOT = common.ROOT
PLAYBOOKS = ROOT / "ansible/playbooks"
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
GROUPS = ("wireguard", "k3s_servers", "k3s_agents", "storage_stateful", "ingress")
INGRESS_LABELS = ["cvp.io/ingress=true", "svccontroller.k3s.cattle.io/enablelb=true",
                  "svccontroller.k3s.cattle.io/lbpool=public"]
STORAGE_PATH = "/var/lib/rancher/k3s/storage"


class NodeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise NodeError(message)


def say(message):
    print(message, flush=True)


def known_hosts_file():
    return Path.home() / ".ssh/known_hosts"


def atomic_write(path, content, mode):
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def make_directories(path):
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def private_directory(path):
    make_directories(path)
    info = path.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
            f"{path} must be a private directory (mode 0700) owned by you")


def quote(value):
    return json.dumps(value)


def flow(values):
    return "[" + ", ".join(quote(value) for value in values) + "]"


def run(argv, *, capture=False, check=True, env=None):
    result = subprocess.run(argv, cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    if check and result.returncode:
        detail = (result.stderr or "").strip().splitlines()[-1:] if capture else []
        raise NodeError(f"command failed ({result.returncode}): {shlex.join(argv[:4])} ..."
                        + (f"\n  {detail[0]}" if detail else ""))
    return result


def ansible_env():
    env = dict(os.environ)
    env.update(ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), ANSIBLE_HOST_KEY_CHECKING="True",
               ANSIBLE_SSH_HOST_KEY_CHECKING="True", ANSIBLE_TRANSPORT="ssh")
    return env


def read_inventory(inventory):
    result = run(["ansible-inventory", *common.inventory_args(inventory), "--list"], capture=True, env=ansible_env())
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise NodeError("could not parse the resolved Ansible inventory") from None
    for values in data.get("_meta", {}).get("hostvars", {}).values():
        require(values.get("ansible_connection", "ssh") in {"ssh", "ansible.builtin.ssh"},
                "guarded host operations require the SSH connection plugin")
    return data


def members(data, group):
    return data.get(group, {}).get("hosts", [])


# --- WireGuard keys ---------------------------------------------------------

def wireguard_public_key(private):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    raw = base64.b64decode(private, validate=True)
    require(len(raw) == 32, "WireGuard private keys are 32 bytes")
    public = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.b64encode(public.public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)).decode()


def generate_wireguard_key():
    key = bytearray(os.urandom(32))
    key[0] &= 248  # Clamp exactly like `wg genkey`.
    key[31] = (key[31] & 127) | 64
    return base64.b64encode(bytes(key)).decode()


# --- node-new ---------------------------------------------------------------

def operator_file_for_write():
    explicit = os.environ.get("CVP_OPERATOR_CONFIG_FILE", "")
    path = Path(explicit) if explicit else common.config_dir() / "operator.yml"
    require(path.is_absolute(), "CVP_OPERATOR_CONFIG_FILE must be an absolute path")
    resolved = path.resolve()
    require(resolved != ROOT and ROOT not in resolved.parents,
            "the operator configuration must live outside the repository")
    return resolved


def allocate_address(existing, requested):
    used = {ipaddress.IPv4Address(address) for address in existing}
    networks = {ipaddress.IPv4Network(f"{address}/24", strict=False) for address in used}
    require(len(networks) <= 1, "existing WireGuard addresses do not share one /24 mesh")
    if requested:
        try:
            address = ipaddress.IPv4Address(requested)
        except ipaddress.AddressValueError:
            raise NodeError("--mesh-address must be a bare IPv4 address") from None
        network = ipaddress.IPv4Network(f"{address}/24", strict=False)
        require(not networks or network in networks, f"--mesh-address must be inside the existing mesh {next(iter(networks), '')}")
        require(address.is_private, "--mesh-address must be in a private (RFC1918) range")
        require(address not in used, "--mesh-address is already assigned")
        require(address not in (network.network_address, network.broadcast_address),
                "--mesh-address must be a usable host address")
        return str(address)
    require(networks, "the first node needs an explicit --mesh-address in an unused RFC1918 /24")
    for address in next(iter(networks)).hosts():
        if address not in used:
            return str(address)
    raise NodeError("the mesh /24 has no free addresses")


def host_cidr(value, option):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise NodeError(f"{option} must be a host CIDR such as 203.0.113.10/32") from None
    require(network.prefixlen == network.max_prefixlen, f"{option} must be a single-address /32 or /128")
    return network


def endpoint_for(address, port):
    try:
        if ipaddress.ip_address(address).version == 6:
            return f"[{address}]:{port}"
    except ValueError:
        pass
    return f"{address}:{port}"


def render_host_vars(values):
    lines = [
        "---",
        "# Generated by `task node-new`. Review, then run `task node-join`.",
        f"ansible_host: {quote(values['ssh'])}",
        f"ansible_port: {values['ssh_port']}",
        f"ansible_private_key_file: {quote(values['ssh_key'])}",
        f"node_name: {values['node']}",
        f"node_virtualization: {values['virt']}",
        "",
        f"wireguard_address: {quote(values['address'])}",
        f"wireguard_endpoint: {quote(values['endpoint'])}",
        f"wireguard_public_key: {quote(values['public_key'])}",
        "",
        'tailscale_address: ""',
        f"tailscale_advertise_tags: {flow(values['tags'])}",
        f"k3s_role: {values['role']}",
        f"k3s_server_init: {'true' if values['init'] else 'false'}",
        "k3s_tls_sans: []",
        "k3s_node_labels:",
        *(f"  - {label}" for label in values["labels"]),
        "k3s_node_taints: []",
        "",
        f"storage_enabled: {'true' if values['storage'] else 'false'}",
        'storage_device: ""',
    ]
    if values["storage"]:
        lines.append(f"storage_mountpoint: {STORAGE_PATH}")
    lines += ["storage_manage_device: false", "storage_allow_format: false", ""]
    return "\n".join(lines)


def show_diff(path, before, after):
    sys.stdout.writelines(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}"))


def cmd_new(args):
    node = args.node
    require(NAME.fullmatch(node) is not None, "node names are lowercase letters, digits, and hyphens")
    inventory = Path(args.inventory).resolve()
    host_vars_dir = inventory.parent / "host_vars"
    host_vars = host_vars_dir / f"{node}.yml"
    inventory_text = inventory.read_text()
    data = yaml.safe_load(inventory_text)
    require(isinstance(data, dict) and isinstance(data.get("all"), dict), "inventory must have an all mapping")
    shared = data["all"].setdefault("vars", {})
    children = data["all"].setdefault("children", {})
    groups = {}
    for group in GROUPS:
        entry = children.setdefault(group, {}) or {}
        children[group] = entry
        entry["hosts"] = entry.get("hosts") or {}
        groups[group] = entry["hosts"]
    require(not any(node in hosts for hosts in groups.values()) and node not in children,
            f"{node} is already in the inventory")
    require(not host_vars.exists(), f"{host_vars} already exists")

    mesh = list(groups["wireguard"])
    first = not mesh
    existing = {}
    for name in mesh:
        path = host_vars_dir / f"{name}.yml"
        require(path.is_file(), f"existing node {name} has no {path.name}; node-new manages host_vars files")
        existing[name] = yaml.safe_load(path.read_text()) or {}

    role = args.role or ("server" if first else "agent")
    if first:
        require(role == "server", "the first node initializes the cluster and must be a server")
    else:
        require(shared.get("k3s_cluster_init_host") and shared.get("k3s_server_host"),
                "inventory all.vars must already select k3s_cluster_init_host and k3s_server_host")

    address = allocate_address([values["wireguard_address"] for values in existing.values()], args.mesh_address)
    keys = {values.get("ansible_private_key_file") for values in existing.values()}
    ssh_key = args.ssh_key or (keys.pop() if len(keys) == 1 else None)
    require(ssh_key and Path(ssh_key).is_absolute(),
            "--ssh-key must be the absolute path of the operator SSH private key")
    overrides = inventory.parent / "group_vars/all.yml"
    instance_vars = (yaml.safe_load(overrides.read_text()) or {}) if overrides.is_file() else {}
    port = int(instance_vars.get("wireguard_port") or shared.get("wireguard_port") or 51820)
    labels = list(args.label) if args.label else (
        ["cvp.io/compute=true", "cvp.io/storage=true", "cvp.io/system=true"] if first else ["cvp.io/compute=true"])
    if first:
        labels += [label for label in INGRESS_LABELS if label not in labels]
    storage = first if args.storage is None else args.storage
    sources = [host_cidr(value, "--ssh-source") for value in args.ssh_source]
    require(sources, "--ssh-source is required: the controller's public egress address as /32 or /128")

    config_dir = common.config_dir()
    key_path = Path(args.wireguard_key_file) if args.wireguard_key_file else config_dir / "keys" / f"{node}.wg-private"
    require(key_path.is_absolute(), "--wireguard-key-file must be absolute")
    operator_path = operator_file_for_write()
    if args.tailscale_auth_key_file:
        tailscale = {"file": str(common.external_path(args.tailscale_auth_key_file))}
    else:
        variable = args.tailscale_auth_key_env or node.upper().replace("-", "_") + "_TAILSCALE_AUTH_KEY"
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable) is not None, "invalid --tailscale-auth-key-env")
        tailscale = {"env": variable}
        if args.write:
            require(os.environ.get(variable), f"export {variable} from your secret store first, "
                                              "or pass --tailscale-auth-key-file")

    new_key = not key_path.exists()
    if new_key:
        private_key = generate_wireguard_key() if args.write else None
    else:
        private_key = common.private_bytes(key_path).decode().strip()
    public_key = wireguard_public_key(private_key) if private_key else "<generated on --write>"
    existing_keys = {values.get("wireguard_public_key") for values in existing.values()}
    require(public_key not in existing_keys, f"{key_path} belongs to another node's WireGuard identity")

    values = dict(node=node, ssh=args.ssh, ssh_port=args.ssh_port, ssh_key=ssh_key, virt=args.virt,
                  address=address, endpoint=args.endpoint or endpoint_for(args.ssh, port), public_key=public_key,
                  tags=["tag:k3s", "tag:k3s-ingress"] if first else ["tag:k3s"], role=role, init=first,
                  labels=labels, storage=storage)
    host_text = render_host_vars(values)

    groups["wireguard"][node] = {}
    groups["k3s_servers" if role == "server" else "k3s_agents"][node] = {}
    if first:
        groups["ingress"][node] = {}
        shared["k3s_cluster_init_host"] = node
        shared["k3s_server_host"] = node
    new_inventory = "---\n" + yaml.safe_dump(data, sort_keys=False, default_flow_style=False)

    operator_text = operator_path.read_text() if operator_path.exists() else None
    operator = (yaml.safe_load(operator_text) if operator_text else None) or {"cvp_operator_defaults": {}}
    hosts = operator.setdefault("cvp_operator_hosts", {}) or {}
    operator["cvp_operator_hosts"] = hosts
    require(node not in hosts, f"the operator configuration already has an entry for {node}")
    entry = {
        "wireguard_private_key": {"file": str(key_path)},
        "tailscale_auth_key": tailscale,
        "firewall_ssh_ipv4_source_cidrs": [str(net) for net in sources if net.version == 4],
        "firewall_ssh_ipv6_source_cidrs": [str(net) for net in sources if net.version == 6],
    }
    hosts[node] = entry

    def shown(path):
        instance = common.instance_dir()
        return path.relative_to(instance) if instance in path.parents else path

    relative = shown(inventory)
    say(f"Plan for {node} ({'first host, cluster init' if first else role}, mesh {address}):\n")
    show_diff(relative, inventory_text, new_inventory)
    show_diff(shown(host_vars), "", host_text)
    say(f"\n{operator_path}: add cvp_operator_hosts.{node}:")
    say("  " + yaml.safe_dump(entry, sort_keys=False).replace("\n", "\n  ").rstrip())
    say(f"{key_path}: {'generate a new' if new_key else 'reuse the existing'} WireGuard private key (mode 0600)")
    if operator_text and "#" in operator_text:
        say("note: rewriting the operator file drops its YAML comments")
    if not args.write:
        say("\nDry run only. Review the plan, then rerun with --write.")
        return 0

    created = []
    try:
        if new_key:
            private_directory(key_path.parent)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(private_key + "\n")
            created.append(key_path)
        make_directories(operator_path.parent)
        atomic_write(operator_path, ("---\n" + yaml.safe_dump(operator, sort_keys=False)).encode(), 0o600)
        host_vars_dir.mkdir(exist_ok=True)
        atomic_write(host_vars, host_text.encode(), 0o644)
        created.append(host_vars)
        atomic_write(inventory, new_inventory.encode(), inventory.stat().st_mode & 0o777)
        say("\nValidating the effective inventory (controller only)...")
        env = ansible_env()
        env["CVP_OPERATOR_CONFIG_FILE"] = str(operator_path)
        for variable in ("CVP_OPERATOR_CONFIG_SHA256", "CVP_OPERATOR_FILES_SHA256", "CVP_OPERATOR_CONFIG_ABSENT"):
            env.pop(variable, None)
        result = run(["ansible-playbook", *common.inventory_args(inventory), str(PLAYBOOKS / "validate-inventory.yml")],
                     capture=True, check=False, env=env)
        if result.returncode:
            sys.stderr.write(result.stdout[-4000:] + result.stderr[-2000:])
            raise NodeError("the resulting inventory failed validation; no changes were kept")
    except BaseException:
        atomic_write(inventory, inventory_text.encode(), inventory.stat().st_mode & 0o777)
        if operator_text is None:
            operator_path.unlink(missing_ok=True)
        else:
            atomic_write(operator_path, operator_text.encode(), 0o600)
        for path in created:
            path.unlink(missing_ok=True)
        raise
    if args.no_next_steps:
        return 0
    say(f"\n{node} is in the inventory. Store {key_path} in your external secret store, then run:")
    say(f"  task node-bootstrap -- {node} --confirm {node} --host-key-fingerprint SHA256:<provider console>")
    say(f"  task node-join -- {node} --confirm {node}"
        + ("" if first or role == "agent" else f" --server-confirm {node}"))
    return 0


# --- shared operator pinning -----------------------------------------------

PIN_VARIABLES = ("CVP_OPERATOR_CONFIG_SHA256", "CVP_OPERATOR_FILES_SHA256", "CVP_OPERATOR_CONFIG_ABSENT")


def pin_operator():
    """Validate the operator configuration and pin it (or its absence) for every later stage."""
    for variable in PIN_VARIABLES:
        os.environ.pop(variable, None)
    path = common.operator_path()
    if not path:
        os.environ["CVP_OPERATOR_CONFIG_ABSENT"] = "1"
        return {}, "absent"
    data, digest, files = common.operator_config(path, with_digest="files")
    os.environ.update(CVP_OPERATOR_CONFIG_FILE=str(path), CVP_OPERATOR_CONFIG_SHA256=digest,
                      CVP_OPERATOR_FILES_SHA256=files)
    return data, digest + files


def require_operator_hosts(operator, inventory_data):
    require(set(operator.get("cvp_operator_hosts", {})) <= set(inventory_data.get("_meta", {}).get("hostvars", {})),
            "operator configuration names a host absent from inventory")


def check_operator_pin():
    try:
        path = common.operator_path()
        if path:
            common.operator_config(path)
    except ValueError as error:
        raise NodeError(f"{error}; review it and start a new run") from None


# --- host keys --------------------------------------------------------------

def known_host_name(host, port):
    return host if int(port) == 22 else f"[{host}]:{port}"


def key_fingerprint(line):
    result = subprocess.run(["ssh-keygen", "-lf", "-"], input=line, text=True, capture_output=True)
    require(result.returncode == 0, "ssh-keygen could not fingerprint a host key")
    return result.stdout.split()[1]


def trusted_keys(host, port):
    path = known_hosts_file()
    if not path.exists():
        return set()
    result = subprocess.run(["ssh-keygen", "-F", known_host_name(host, port), "-f", str(path)],
                            text=True, capture_output=True)
    keys = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and not line.startswith("#") and not fields[0].startswith("@"):
            keys.add((fields[1], fields[2]))
    return keys


def scan_keys(host, port):
    result = subprocess.run(["ssh-keyscan", "-T", "10", "-p", str(port), "-t", "ed25519", host],
                            text=True, capture_output=True)
    keys = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and not line.startswith("#"):
            keys.add((fields[1], fields[2]))
    require(keys, f"could not read an ed25519 host key from {host}:{port}")
    return keys


def remember_key(host, port, key):
    path = known_hosts_file()
    private_directory(path.parent)
    with open(path, "a") as stream:
        stream.write(f"{known_host_name(host, port)} {key[0]} {key[1]}\n")
    path.chmod(0o600)


def trust_bootstrap_key(host, port, fingerprint):
    trusted = trusted_keys(host, port)
    if not fingerprint:
        require(trusted, f"{host} is not in {known_hosts_file()}: compare its key with the provider console "
                         "and pass --host-key-fingerprint SHA256:...")
        return
    require(fingerprint.startswith("SHA256:"), "--host-key-fingerprint must be a SHA256: fingerprint")
    matching = [key for key in scan_keys(host, port) if key_fingerprint(f"x {key[0]} {key[1]}") == fingerprint]
    require(matching, f"{host}:{port} did not present the expected host key {fingerprint}; do not continue")
    if trusted:
        require(matching[0] in trusted, f"{known_hosts_file()} already holds a different key for {host}")
        return
    remember_key(host, port, matching[0])
    say(f"Trusted {host}:{port} host key {fingerprint}.")


# --- node-join --------------------------------------------------------------

def state_path(node, inventory):
    directory = common.state_dir() / "nodes"
    private_directory(directory)
    scope = hashlib.sha256(str(inventory).encode()).hexdigest()[:12]
    return directory / f"{node}-{scope}.json"


def load_state(path):
    if not path.exists():
        return {"fingerprint": "", "stages": {}}
    return json.loads(common.private_bytes(path))


def save_state(path, state):
    atomic_write(path, json.dumps(state, indent=2, sort_keys=True).encode(), 0o600)


def operator_ssh_check(inventory, node, ssh):
    options = dict(ssh, ansible_ssh_extra_args="-o BatchMode=yes")
    result = run(["ansible", *common.inventory_args(inventory), node, "-o", "-m", "ansible.builtin.command", "-a", "id -un",
                  "-e", json.dumps(options)], capture=True, check=False, env=ansible_env())
    return result.returncode == 0 and "root" in result.stdout


def cmd_join(args):
    node = args.node
    require(NAME.fullmatch(node) is not None, "node names are lowercase letters, digits, and hyphens")
    require(args.confirm == node, f"pass --confirm {node} after reviewing the host and deployment gates")
    # Reject an invalid or misplaced operator configuration before running anything.
    operator, fingerprint = pin_operator()
    inventory = Path(args.inventory).resolve()
    data = read_inventory(inventory)
    require_operator_hosts(operator, data)
    require(node in members(data, "wireguard"), f"{node} must be in the wireguard group (run task node-new)")
    host = data["_meta"]["hostvars"][node]
    first = bool(host.get("k3s_server_init"))
    if first:
        require(not args.existing_cluster, "this command joins existing clusters only; the target is the init server")
        require(members(data, "wireguard") == [node] and host.get("k3s_cluster_init_host") == node,
                "only the sole inventory node may initialize the cluster")
    server = host.get("k3s_role") == "server"
    require(first or not server or args.server_confirm == node,
            f"joining another etcd server changes quorum; pass --server-confirm {node} after review")
    require(args.server_confirm in (None, "", node), "--server-confirm must equal the joining node")

    ssh = common.ssh_options()
    trust_bootstrap_key(host["ansible_host"], host.get("ansible_port", 22), args.host_key_fingerprint)
    onboard = json.dumps({"cvp_onboard_node": node, "cvp_onboard_server_confirm": args.server_confirm or ""})

    def playbook(name, *extra):
        return ["ansible-playbook", *common.inventory_args(inventory), str(PLAYBOOKS / name), "-e", json.dumps(ssh), *extra]

    stages = [("validate", False, ["ansible-playbook", *common.inventory_args(inventory),
                                   str(PLAYBOOKS / "validate-inventory.yml")]),
              ("access", True, None),
              ("probe", False, playbook("probe.yml", "--limit", node))]
    if not first:
        stages.append(("preflight", False, playbook("onboard-preflight.yml", "-e", onboard)))
    site = playbook("site.yml", *([] if first else ["-e", onboard]))
    if args.preview:
        stages.append(("preview", False, [*site, "--check", "--diff"]))
    else:
        stages += [("site", True, site),
                   ("mesh", False, playbook("probe-wireguard.yml", "--limit", node)),
                   ("verify", False, playbook("verify.yml"))]

    path = state_path(node, inventory)
    state = load_state(path)
    digest = hashlib.sha256((json.dumps(data, sort_keys=True) + fingerprint).encode()).hexdigest()
    if state["fingerprint"] != digest:
        # Inputs changed: completed stages must run again, but an interrupted
        # mutating stage still needs an explicit review before any retry.
        state = {"fingerprint": digest,
                 "stages": {name: status for name, status in state["stages"].items() if status == "started"}}
    if args.restart:
        require(not any(status == "started" for status in state["stages"].values()) or args.retry_reviewed,
                "an interrupted mutating stage needs --retry-reviewed even with --restart")
        state["stages"] = {}
    names = [name for name, _, _ in stages]
    done = [name for name in names if state["stages"].get(name) == "done"]
    if not args.preview and done == names:
        say(f"{node} already completed every join stage with these inputs; nothing to do.")
        return 0
    # Skip only what precedes the last completed mutating stage. Read-only live
    # checks before any pending mutation always run again on fresh state.
    last = max((index for index, (name, mutating, _) in enumerate(stages)
                if mutating and state["stages"].get(name) == "done"), default=-1)
    if last >= 0:
        say(f"Resuming {node} after completed stage '{names[last]}'.")

    for index, (name, mutating, argv) in enumerate(stages):
        if index <= last and name != "validate":
            continue
        if mutating and state["stages"].get(name) == "started":
            require(args.retry_reviewed,
                    f"stage '{name}' was interrupted. Inspect lifecycle locks, services, and journals on the "
                    "affected hosts (see docs/runbooks/nodes.md#6-if-a-stage-fails), then rerun with --retry-reviewed")
        check_operator_pin()
        say(f"\n==> {name}")
        if mutating:
            state["stages"][name] = "started"
            save_state(path, state)
        if name == "access":
            if not operator_ssh_check(inventory, node, ssh):
                prepare_access(args, node, host)
        else:
            run(argv, env=ansible_env())
        if name != "preview":
            state["stages"][name] = "done"
            save_state(path, state)

    if args.preview:
        say(f"\nPreview complete for {node}. Review the diff, then rerun without --preview.")
        return 0
    say(f"\nJoin verified for {node}.")
    return 0


def prepare_access(args, node, host):
    operator_key = host.get("ansible_private_key_file", "")
    public_key = args.public_key or (operator_key + ".pub" if operator_key else "")
    require(public_key and Path(public_key).is_file() and (args.root_key or args.public_key),
            f"ops cannot log in to {node} yet: run task node-bootstrap -- {node} --confirm {node} first "
            "(or pass --root-key for key-based root access)")
    env = dict(os.environ, CVP_ACCESS_NODE=node, CVP_ACCESS_CONFIRM=node,
               CVP_ACCESS_PUBLIC_KEY_FILE=str(Path(public_key).resolve()))
    if operator_key:
        env["CVP_ACCESS_OPERATOR_IDENTITY_FILE"] = operator_key
    if args.root_key:
        env["CVP_ACCESS_ROOT_IDENTITY_FILE"] = args.root_key
    run([str(ROOT / "scripts/prepare-node-access")], env=env)


# --- node-bootstrap ---------------------------------------------------------

BOOTSTRAP_SCRIPT = ROOT / "scripts/node-bootstrap.sh"
BOOTSTRAP_REMOTE = "cvp-node-bootstrap.sh"  # in the login user's home directory


def operator_public_key(args, host):
    operator_key = host.get("ansible_private_key_file", "")
    public_key = args.public_key or (operator_key + ".pub" if operator_key else "")
    require(public_key and Path(public_key).is_file(),
            "pass --public-key with the operator SSH public key (default: <ansible_private_key_file>.pub)")
    lines = Path(public_key).read_text().splitlines()
    require(len(lines) == 1 and lines[0].strip(), f"{public_key} must contain exactly one SSH public key")
    result = subprocess.run(["ssh-keygen", "-lf", public_key], text=True, capture_output=True)
    require(result.returncode == 0, f"ssh-keygen rejected {public_key}")
    return public_key, lines[0].strip()


class LoginSession:
    """One SSH control connection to a fresh host's provider login.

    The password (if any) is typed once; detection, copy, and run reuse it.
    Host keys must already be trusted (see trust_bootstrap_key).
    """

    def __init__(self, address, port, user="root", key_file=None):
        require(NAME.fullmatch(user) is not None, "--login-user must be a plain account name")
        self.address, self.port, self.user = str(address), int(port), user
        self.control = Path(tempfile.mkdtemp(prefix="cvp-"))
        self.options = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=yes",
                        "-o", f"UserKnownHostsFile={known_hosts_file()}", "-o", "ForwardAgent=no",
                        "-o", "ControlMaster=auto", "-o", f"ControlPath={self.control}/login",
                        "-o", "ControlPersist=900"]
        if key_file:
            self.options += ["-o", "IdentitiesOnly=yes", "-i", str(common.external_path(key_file))]
        self.target = f"{user}@{self.address}"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        subprocess.run(["ssh", *self.options, "-p", str(self.port), "-O", "exit", self.target],
                       capture_output=True)
        shutil.rmtree(self.control, ignore_errors=True)

    def output(self, command):
        result = subprocess.run(["ssh", *self.options, "-p", str(self.port), self.target, command],
                                stdout=subprocess.PIPE, text=True)
        require(result.returncode == 0, f"SSH to {self.target} failed ({result.returncode})")
        return result.stdout

    def client_source(self):
        """The controller address as this host sees it: the SSH source to allow."""
        fields = self.output('printf "%s\\n" "$SSH_CONNECTION"').split()
        require(fields, "the host did not report the SSH client address")
        return ipaddress.ip_address(fields[0])

    def bootstrap(self, key):
        copy_target = f"{self.user}@[{self.address}]" if ":" in self.address else self.target
        say(f"==> copying the bootstrap script to {self.address}")
        run(["scp", *self.options, "-P", str(self.port), str(BOOTSTRAP_SCRIPT),
             f"{copy_target}:{BOOTSTRAP_REMOTE}"])
        say(f"==> running the bootstrap script on {self.address} as root")
        sudo = "" if self.user == "root" else "sudo "
        remote = (f"{sudo}sh {BOOTSTRAP_REMOTE} {shlex.quote(key)}; status=$?; "
                  f"rm -f {BOOTSTRAP_REMOTE}; exit $status")
        run(["ssh", *self.options, "-t", "-p", str(self.port), self.target, remote])


def cmd_bootstrap(args):
    node = args.node
    require(NAME.fullmatch(node) is not None, "node names are lowercase letters, digits, and hyphens")
    require(args.confirm == node, f"pass --confirm {node} after checking the host is the fresh {node} install")
    inventory = Path(args.inventory).resolve()
    data = read_inventory(inventory)
    require(node in members(data, "wireguard"), f"{node} must be in the wireguard group (run task node-new)")
    host = data["_meta"]["hostvars"][node]
    require(host.get("ansible_user", "ops") == "ops", "the bootstrap creates the ops operator; keep ansible_user: ops")
    address, port = host["ansible_host"], host.get("ansible_port", 22)
    _, key = operator_public_key(args, host)
    trust_bootstrap_key(address, port, args.host_key_fingerprint)
    say(f"==> connecting to {address} as {args.login_user} (you may be asked for its password once)")
    with LoginSession(address, port, args.login_user, args.root_key) as session:
        session.bootstrap(key)
    say("==> verifying ops login and passwordless sudo with the operator key")
    require(operator_ssh_check(inventory, node, common.ssh_options()),
            "ops could not log in and escalate with the operator key; inspect the bootstrap output above")
    say(f"\n{node} is ready for Ansible. Next: task node-join -- {node} --confirm {node}")
    return 0


# --- entry point ------------------------------------------------------------

def parser():
    root = argparse.ArgumentParser(prog="cvp-node", description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = root.add_subparsers(dest="command", required=True)

    new = commands.add_parser("new", help="scaffold one node (controller only)")
    new.add_argument("node")
    new.add_argument("--ssh", required=True, help="bootstrap SSH address (public IP or DNS name)")
    new.add_argument("--ssh-port", type=int, default=22)
    new.add_argument("--virt", required=True, choices=("vm", "lxc", "metal"))
    new.add_argument("--role", choices=("agent", "server"))
    new.add_argument("--mesh-address", help="WireGuard IPv4; required for the first node, else next free")
    new.add_argument("--endpoint", help="public WireGuard endpoint (default: --ssh address and mesh port)")
    new.add_argument("--ssh-key", help="absolute operator SSH private key path (default: shared by existing nodes)")
    new.add_argument("--ssh-source", action="append", default=[],
                     help="controller public egress /32 or /128 allowed to SSH (repeatable)")
    new.add_argument("--label", action="append", help="node label key=value (repeatable; replaces defaults)")
    new.add_argument("--storage", action=argparse.BooleanOptionalAction, default=None,
                     help="prepare directory-backed local storage (default: first node only)")
    new.add_argument("--wireguard-key-file", help="private key path (default: ~/.config/cvp/keys/<node>.wg-private)")
    auth = new.add_mutually_exclusive_group()
    auth.add_argument("--tailscale-auth-key-file", help="private file holding the Tailscale auth key")
    auth.add_argument("--tailscale-auth-key-env", help="environment variable holding the Tailscale auth key")
    new.add_argument("--inventory", default=str(common.instance_inventory()))
    new.add_argument("--write", action="store_true", help="apply the plan (default: dry run)")
    new.add_argument("--no-next-steps", action="store_true", help=argparse.SUPPRESS)
    new.set_defaults(func=cmd_new)

    join = commands.add_parser("join", help="join one node (resumable)")
    join.add_argument("node")
    join.add_argument("--confirm", default="")
    join.add_argument("--server-confirm")
    join.add_argument("--host-key-fingerprint", help="provider-console SHA256 fingerprint for first contact")
    join.add_argument("--root-key", help="provider root SSH key used only if operator access is missing")
    join.add_argument("--public-key", help="operator public key to install (default: <ssh key>.pub)")
    join.add_argument("--preview", action="store_true", help="stop after a check-mode site diff")
    join.add_argument("--retry-reviewed", action="store_true", help="retry an interrupted mutating stage")
    join.add_argument("--restart", action="store_true", help="ignore completed stages")
    join.add_argument("--existing-cluster", action="store_true", help=argparse.SUPPRESS)
    join.add_argument("--inventory", default=str(common.instance_inventory()))
    join.set_defaults(func=cmd_join)

    bootstrap = commands.add_parser("bootstrap", help="prepare a fresh Debian host over root SSH")
    bootstrap.add_argument("node")
    bootstrap.add_argument("--confirm", default="")
    bootstrap.add_argument("--host-key-fingerprint", help="provider-console SHA256 fingerprint for first contact")
    bootstrap.add_argument("--login-user", default="root",
                           help="provider login account; a non-root account runs the script with sudo")
    bootstrap.add_argument("--root-key", help="SSH private key for the login account (default: password)")
    bootstrap.add_argument("--public-key", help="operator public key to install (default: <ssh key>.pub)")
    bootstrap.add_argument("--inventory", default=str(common.instance_inventory()))
    bootstrap.set_defaults(func=cmd_bootstrap)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (NodeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
