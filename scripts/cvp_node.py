#!/usr/bin/env python3
"""Operator node lifecycle: scaffold a node, join it, and move its SSH private.

new      Write inventory, host vars, a WireGuard key, and the operator entry for
         one node as a single validated transaction. Never contacts a host.
join     Run the guarded join stages in order and record progress, so a rerun
         resumes after the last completed stage. An interrupted mutating stage
         is never retried without --retry-reviewed.
private  Move a joined node's SSH to its Tailscale address after matching the
         private host key against the already-trusted public one.
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
DEFAULT_INVENTORY = ROOT / "ansible/inventory/hosts.yml"
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
GROUPS = ("wireguard", "k3s_servers", "k3s_agents", "storage_stateful", "ingress")
INGRESS_LABELS = ["cvp.io/ingress=true", "svccontroller.k3s.cattle.io/enablelb=true",
                  "svccontroller.k3s.cattle.io/lbpool=public"]
STORAGE_PATH = "/var/lib/rancher/k3s/storage"
TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")
TAILNET_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")


class NodeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise NodeError(message)


def say(message):
    print(message, flush=True)


def xdg(variable, fallback):
    return Path(os.environ.get(variable) or Path.home() / fallback)


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
    result = run(["ansible-inventory", "-i", str(inventory), "--list"], capture=True, env=ansible_env())
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
    path = Path(explicit) if explicit else xdg("XDG_CONFIG_HOME", ".config") / "cvp/operator.yml"
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
    port = int(shared.get("wireguard_port", 51820))
    labels = list(args.label) if args.label else (
        ["cvp.io/compute=true", "cvp.io/storage=true", "cvp.io/system=true"] if first else ["cvp.io/compute=true"])
    if first:
        labels += [label for label in INGRESS_LABELS if label not in labels]
    storage = first if args.storage is None else args.storage
    sources = [host_cidr(value, "--ssh-source") for value in args.ssh_source]
    require(sources, "--ssh-source is required: the controller's public egress address as /32 or /128")

    config_dir = xdg("XDG_CONFIG_HOME", ".config") / "cvp"
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

    relative = inventory.relative_to(ROOT) if ROOT in inventory.parents else inventory
    say(f"Plan for {node} ({'first host, cluster init' if first else role}, mesh {address}):\n")
    show_diff(relative, inventory_text, new_inventory)
    show_diff(host_vars.relative_to(ROOT) if ROOT in host_vars.parents else host_vars, "", host_text)
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
        result = run(["ansible-playbook", "-i", str(inventory), str(PLAYBOOKS / "validate-inventory.yml")],
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
    say(f"\n{node} is in the inventory. Store {key_path} in your external secret store, then run:")
    fingerprint = " --host-key-fingerprint SHA256:<from the provider console>"
    say(f"  task node-join -- {node} --confirm {node}{fingerprint}"
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
    directory = xdg("XDG_STATE_HOME", ".local/state") / "cvp/nodes"
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
    result = run(["ansible", "-i", str(inventory), node, "-o", "-m", "ansible.builtin.command", "-a", "id -un",
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
        return ["ansible-playbook", "-i", str(inventory), str(PLAYBOOKS / name), "-e", json.dumps(ssh), *extra]

    stages = [("validate", False, ["ansible-playbook", "-i", str(inventory),
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
    say(f"\nJoin verified for {node}. Next: task node-private -- {node} --confirm {node}")
    return 0


def prepare_access(args, node, host):
    operator_key = host.get("ansible_private_key_file", "")
    public_key = args.public_key or (operator_key + ".pub" if operator_key else "")
    require(public_key and Path(public_key).is_file(),
            "operator SSH login is not ready: pass --public-key with the operator public key to grant it")
    env = dict(os.environ, CVP_ACCESS_NODE=node, CVP_ACCESS_CONFIRM=node,
               CVP_ACCESS_PUBLIC_KEY_FILE=str(Path(public_key).resolve()))
    if operator_key:
        env["CVP_ACCESS_OPERATOR_IDENTITY_FILE"] = operator_key
    if args.root_key:
        env["CVP_ACCESS_ROOT_IDENTITY_FILE"] = args.root_key
    run([str(ROOT / "scripts/prepare-node-access")], env=env)


# --- node-private -----------------------------------------------------------

def ssh_command(host, port, key, command):
    argv = ["ssh", "-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "ControlMaster=no",
            "-o", "ControlPath=none", "-o", f"UserKnownHostsFile={known_hosts_file()}",
            "-i", key, "-p", str(port), f"ops@{host}", command]
    result = subprocess.run(argv, text=True, capture_output=True, timeout=60)
    require(result.returncode == 0, f"SSH to {host} failed: {result.stderr.strip()[-300:]}")
    return result.stdout.strip()


def replace_scalar(text, key, value):
    pattern = re.compile(rf"^{re.escape(key)}:.*$", re.MULTILINE)
    require(len(pattern.findall(text)) == 1, f"host vars must contain exactly one top-level {key} line")
    return pattern.sub(lambda _: f"{key}: {value}", text)


def tailnet_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address if address in (TAILNET_V4 if address.version == 4 else TAILNET_V6) else None


def cmd_private(args):
    node = args.node
    require(args.confirm == node, f"pass --confirm {node} after reviewing the private access change")
    inventory = Path(args.inventory).resolve()
    data = read_inventory(inventory)
    require(node in members(data, "wireguard"), f"{node} must be in the wireguard group")
    host = data["_meta"]["hostvars"][node]
    public_host, port = host["ansible_host"], host.get("ansible_port", 22)
    key = host.get("ansible_private_key_file", "")
    require(key and Path(key).is_absolute(), f"{node} needs an absolute ansible_private_key_file")
    if tailnet_address(str(public_host)) and host.get("tailscale_address") == public_host:
        say(f"{node} already uses its Tailscale address {public_host}; nothing to do.")
        return 0
    operator, _ = pin_operator()
    require_operator_hosts(operator, data)

    say(f"==> reading {node}'s Tailscale address over the trusted public path")
    reported = ssh_command(public_host, port, key, "tailscale ip -4").splitlines()
    private_host = tailnet_address(reported[0]) if reported else None
    require(private_host is not None, "the node did not report a Tailscale IPv4 address; is it enrolled?")
    private_host = str(private_host)

    say(f"==> matching the host key at {private_host} with the trusted key for {public_host}")
    trusted = trusted_keys(public_host, port)
    require(trusted, f"{public_host} has no trusted key in {known_hosts_file()}")
    scanned = scan_keys(private_host, port)
    match = scanned & trusted
    require(match, f"{private_host} presented a host key that differs from the trusted {public_host} key; stop")
    if not trusted_keys(private_host, port) & match:
        remember_key(private_host, port, next(iter(match)))

    say("==> proving a fresh private login, sudo, and the client source the host sees")
    session = ssh_command(private_host, port, key, 'sudo -n true && printf "%s\\n" "$SSH_CONNECTION"')
    if args.source:
        source = host_cidr(args.source, "--source")
    else:
        client = tailnet_address(session.split()[0]) if session else None
        require(client is not None, "the host did not see a Tailscale client source; "
                                    "pass an independently verified --source CIDR")
        source = ipaddress.ip_network(f"{client}/{client.max_prefixlen}")

    host_vars = inventory.parent / "host_vars" / f"{node}.yml"
    host_text = host_vars.read_text()
    updated = replace_scalar(host_text, "ansible_host", quote(private_host))
    updated = replace_scalar(updated, "tailscale_address", quote(private_host))
    if host.get("k3s_role") == "server":
        sans = list(host.get("k3s_tls_sans") or [])
        if private_host not in sans:
            updated = replace_scalar(updated, "k3s_tls_sans", flow([*sans, private_host]))
    parsed = yaml.safe_load(updated)
    require(parsed["ansible_host"] == private_host and parsed["tailscale_address"] == private_host,
            "host vars rewrite did not produce the expected values")

    operator_path = common.operator_path()
    require(operator_path is not None, "the operator configuration is required to move SSH sources")
    operator_text = operator_path.read_text()
    operator = yaml.safe_load(operator_text)
    entry = operator.get("cvp_operator_hosts", {}).get(node)
    require(isinstance(entry, dict), f"the operator configuration has no entry for {node}")
    entry["firewall_ssh_ipv4_source_cidrs"] = [str(source)] if source.version == 4 else []
    entry["firewall_ssh_ipv6_source_cidrs"] = [str(source)] if source.version == 6 else []
    new_operator = "---\n" + yaml.safe_dump(operator, sort_keys=False)

    show_diff(host_vars.name, host_text, updated)
    say(f"{operator_path}: SSH sources for {node} -> {source}")
    atomic_write(host_vars, updated.encode(), host_vars.stat().st_mode & 0o777)
    atomic_write(operator_path, new_operator.encode(), 0o600)
    try:
        operator, _ = pin_operator()
        require_operator_hosts(operator, read_inventory(inventory))
        say("==> proving Ansible reaches the node over the private address")
        require(operator_ssh_check(inventory, node, common.ssh_options()),
                "Ansible could not log in and escalate over the private address")
    except BaseException:
        atomic_write(host_vars, host_text.encode(), host_vars.stat().st_mode & 0o777)
        atomic_write(operator_path, operator_text.encode(), 0o600)
        say("Restored the previous host vars and operator settings; public SSH is unchanged.")
        raise

    ssh = json.dumps(common.ssh_options())
    for name, argv in (("probe", ["probe.yml", "--limit", node]), ("site", ["site.yml"]),
                       ("mesh", ["probe-wireguard.yml", "--limit", node]), ("verify", ["verify.yml"])):
        check_operator_pin()
        say(f"\n==> {name}")
        run(["ansible-playbook", "-i", str(inventory), str(PLAYBOOKS / argv[0]), "-e", ssh, *argv[1:]],
            env=ansible_env())
    say(f"\n{node} now uses private SSH at {private_host} from {source}.")
    say("Remove the provider-firewall public SSH exception; keep UDP "
        f"{host.get('wireguard_port', 51820)} open for the mesh.")
    if host.get("k3s_role") == "server":
        say(f"The API certificate now covers {private_host}; see the kubeconfig export step in docs/runbooks/nodes.md.")
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
    new.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    new.add_argument("--write", action="store_true", help="apply the plan (default: dry run)")
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
    join.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    join.set_defaults(func=cmd_join)

    private = commands.add_parser("private", help="move SSH to the Tailscale address")
    private.add_argument("node")
    private.add_argument("--confirm", default="")
    private.add_argument("--source", help="verified controller /32 or /128 (default: read from the session)")
    private.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    private.set_defaults(func=cmd_private)
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
