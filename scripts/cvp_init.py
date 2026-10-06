#!/usr/bin/env python3
"""Guided setup: take a freshly installed Debian host to a joined cluster node.

Run `task init` once per host. The first run creates the cluster; every later
run adds one node. It asks only for what it cannot detect, shows every plan
before writing, and is safe to rerun: completed steps are skipped and the join
resumes where it stopped. Every answer can also be given as a flag.
"""

import argparse
import getpass
import ipaddress
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

try:
    import yaml  # noqa: F401  (cvp_node needs the pinned Ansible Python)
except ImportError:
    executable = shutil.which("ansible-playbook")
    if not executable or os.environ.get("CVP_INIT_ANSIBLE_PYTHON"):
        sys.exit("error: task init requires the pinned Ansible Python environment (run it through task)")
    interpreter = shlex.split(Path(executable).resolve().read_text().splitlines()[0].removeprefix("#!"))
    os.environ["CVP_INIT_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cvp_node as node_cli  # noqa: E402
from cvp_node import NodeError, ROOT, require, say  # noqa: E402

COLLECTIONS = ROOT / "ansible/collections/ansible_collections"
FIRST_MESH_ADDRESS = "10.77.0.1"
TAILNET = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))

RULES = """\
Network rules this setup enforces:
  public IP  : SSH from your address only, Cloudflare HTTP(S) to the ingress node,
               and the encrypted WireGuard transport (UDP 51820)
  WireGuard  : node-to-node cluster traffic only
  Tailscale  : people reaching internal services (Kubernetes API, internal apps)
"""

FINGERPRINT_HELP = """\
Open the provider's web console for this host (not SSH) and run:
    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
Copy the SHA256:... value. It proves the host you reach over the network is yours.
"""


class Wizard:
    def __init__(self, args):
        self.args = args
        self.interactive = sys.stdin.isatty()
        self.assume_yes = args.yes or not self.interactive
        self.inventory = Path(args.inventory).resolve()

    # -- prompting -----------------------------------------------------------

    def ask(self, label, value=None, default=None, flag=None, check=None, secret=False):
        while True:
            if value is None and not self.interactive and default:
                value = default
            if value is None:
                require(self.interactive, f"{label}: pass {flag} (no terminal to ask on)")
                suffix = f" [{default}]" if default else ""
                prompt = f"{label}{suffix}: "
                answer = (getpass.getpass(prompt) if secret else input(prompt)).strip()
                value = answer or default
            if value and (check is None or check(value)):
                return value
            require(self.interactive, f"{label}: invalid value {value!r}")
            say("  invalid value, try again")
            value = None

    def confirm(self, question, default=True):
        if self.assume_yes:
            return True
        answer = input(f"{question} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        return default if not answer else answer in ("y", "yes")

    def step(self, text):
        say(f"\n=== {text}")

    # -- steps ---------------------------------------------------------------

    def controller(self):
        self.step("Checking the controller")
        for tool in ("ansible-playbook", "ansible-inventory", "ssh", "scp", "ssh-keygen", "ssh-keyscan"):
            require(shutil.which(tool), f"{tool} is missing: run `mise install` and use `task init`")
        if not (COLLECTIONS / "kubernetes/core").is_dir():
            say("Installing the pinned Ansible collections...")
            node_cli.run(["ansible-galaxy", "collection", "install", "-r", str(ROOT / "ansible/requirements.yml"),
                          "-p", str(ROOT / "ansible/collections")], env=node_cli.ansible_env())
        key = Path(self.args.ssh_key or Path.home() / ".ssh/cvp-ops")
        require(key.is_absolute(), "--ssh-key must be an absolute path")
        if not key.exists():
            require(self.confirm(f"Create the operator SSH key {key}?"), "an operator SSH key is required")
            node_cli.make_directories(key.parent)
            node_cli.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "cvp-ops", "-f", str(key)])
            say(f"Created {key} (keep it safe; it is your SSH access to every node)")
        require(key.with_suffix(".pub").is_file(), f"{key}.pub is missing")
        self.ssh_key = str(key)

    def choose_node(self):
        self.data = node_cli.read_inventory(self.inventory)
        mesh = node_cli.members(self.data, "wireguard")
        self.first = not mesh
        default = "server1" if self.first else next(
            f"worker{index}" for index in range(1, 1000) if f"worker{index}" not in mesh)
        say("Creating a new cluster with its first host." if self.first
            else f"Adding a host to the cluster ({', '.join(sorted(mesh))}).")
        self.node = self.ask("Node name", self.args.node, default, "--node",
                             lambda value: node_cli.NAME.fullmatch(value) is not None)
        self.existing = self.node in mesh
        if self.existing:
            say(f"{self.node} is already in the inventory: resuming its setup.")
            host = self.data["_meta"]["hostvars"][self.node]
            self.address, self.port = str(host["ansible_host"]), int(host.get("ansible_port", 22))
            self.role = host.get("k3s_role", "agent")
            self.first = bool(host.get("k3s_server_init"))

    def describe_host(self):
        if self.existing:
            return
        self.address = self.ask("Public IP address of the host", self.args.address, None, "--address",
                                valid_ip)
        self.port = int(self.args.ssh_port)
        self.virt = self.ask("Virtualization (vm, lxc, metal)", self.args.virt, "vm", "--virt",
                             lambda value: value in ("vm", "lxc", "metal"))
        if self.first:
            self.role = "server"
            say("The first host is the cluster's init server and its ingress node.")
            self.mesh = self.ask("Private mesh address for this host (in an unused RFC1918 /24)",
                                 self.args.mesh_address, FIRST_MESH_ADDRESS, "--mesh-address", valid_ip)
        else:
            self.role = self.ask("Role (agent, server)", self.args.role, "agent", "--role",
                                 lambda value: value in ("agent", "server"))
            self.mesh = self.args.mesh_address

    def trust_host(self):
        if self.existing and node_cli.trusted_keys(self.address, self.port):
            return
        self.step(f"Verifying the SSH host key of {self.address}")
        if self.args.host_key_fingerprint is None and self.interactive:
            say(FINGERPRINT_HELP)
        fingerprint = self.ask("Host key fingerprint", self.args.host_key_fingerprint, None,
                               "--host-key-fingerprint", lambda value: value.startswith("SHA256:"))
        node_cli.trust_bootstrap_key(self.address, self.port, fingerprint)

    def tailscale_key(self):
        path = Path(self.args.tailscale_auth_key_file or
                    node_cli.xdg("XDG_CONFIG_HOME", ".config") / "cvp/keys" / f"{self.node}.ts-authkey")
        if path.exists():
            return str(path)
        self.step("Tailscale enrollment key")
        say("Create a reusable or one-off auth key in the Tailscale admin console, tagged "
            + ("tag:k3s and tag:k3s-ingress." if self.first else "tag:k3s."))
        value = self.ask("Paste the Tailscale auth key (hidden)", None, None, "--tailscale-auth-key-file",
                         lambda text: text.startswith("tskey-") and "\n" not in text, secret=True)
        node_cli.private_directory(path.parent)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(value + "\n")
        say(f"Saved to {path} (mode 0600)")
        return str(path)

    def detect_source(self, session):
        if self.args.ssh_source:
            return self.args.ssh_source
        client = session.client_source()
        require(not any(client in network for network in TAILNET),
                "you reached the host over Tailscale; SSH must use its public address")
        source = f"{client}/{client.max_prefixlen}"
        say(f"The host sees your SSH connection coming from {client}.")
        say("Only this address will be allowed to SSH to the node afterwards; prefer a stable one.")
        if not self.confirm(f"Allow SSH from {source}?"):
            source = self.ask("SSH source address (/32 or /128)", None, None, "--ssh-source",
                              lambda value: "/" in value)
        return source

    def scaffold(self, source, tailscale_file):
        argv = ["new", self.node, "--inventory", str(self.inventory), "--ssh", self.address,
                "--ssh-port", str(self.port), "--virt", self.virt, "--role", self.role,
                "--ssh-key", self.ssh_key, "--ssh-source", source,
                "--tailscale-auth-key-file", tailscale_file]
        if self.mesh:
            argv += ["--mesh-address", self.mesh]
        self.step("Inventory plan")
        call(argv)
        require(self.confirm("Write these files?"), "nothing was written")
        call([*argv, "--write", "--no-next-steps"])

    def prepare_host(self):
        if self.existing and self.operator_ready():
            return
        tailscale_file = self.tailscale_key() if not self.existing else None
        login = self.args.login_user
        self.step(f"Connecting to {self.address} as {login} (enter its password if asked)")
        with node_cli.LoginSession(self.address, self.port, login, self.args.root_key) as session:
            if not self.existing:
                source = self.detect_source(session)
                self.scaffold(source, tailscale_file)
            public_key = Path(self.ssh_key + ".pub").read_text().strip()
            session.bootstrap(public_key)
        require(self.operator_ready(), "ops could not log in and use sudo after the bootstrap; see the output above")
        say("ops login and passwordless sudo verified.")

    def operator_ready(self):
        return node_cli.operator_ssh_check(self.inventory, self.node, node_cli.common.ssh_options())

    def join(self):
        self.step(f"Joining {self.node} to the cluster (several minutes)")
        argv = ["join", self.node, "--confirm", self.node, "--inventory", str(self.inventory)]
        if self.args.retry_reviewed:
            argv.append("--retry-reviewed")
        if self.role == "server" and not self.first:
            say("Adding another server changes etcd quorum: two servers tolerate no failure, three tolerate one.")
            confirmation = self.args.server_confirm
            if confirmation is None:
                confirmation = self.ask(f"Type {self.node} to confirm", None, None, "--server-confirm")
            argv += ["--server-confirm", confirmation]
        call(argv)

    def kubeconfig(self):
        output = Path(self.args.kubeconfig or node_cli.xdg("XDG_CONFIG_HOME", ".config") / "cvp/kubeconfig")
        if not self.first or self.args.skip_kubeconfig:
            return None
        if output.exists():
            say(f"Kubeconfig already exported to {output}.")
            return output
        self.step("Exporting a TLS-verified kubeconfig over Tailscale")
        result = subprocess.run(
            ["ssh", "-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
             "-o", f"UserKnownHostsFile={node_cli.known_hosts_file()}", "-o", "IdentitiesOnly=yes",
             "-i", self.ssh_key, "-p", str(self.port), f"ops@{self.address}", "tailscale ip -4"],
            text=True, capture_output=True, timeout=60)
        addresses = result.stdout.split()
        require(result.returncode == 0 and addresses and valid_ip(addresses[0]),
                "could not read the server's Tailscale address; is the controller on the tailnet?")
        env = dict(os.environ, CVP_KUBECONFIG_HOST=self.node, CVP_KUBECONFIG_CONFIRM=self.node,
                   CVP_KUBECONFIG_CONTEXT="cvp", CVP_KUBECONFIG_SERVER=f"https://{addresses[0]}:6443",
                   CVP_KUBECONFIG_OUTPUT=str(output))
        node_cli.run([str(ROOT / "scripts/export-kubeconfig")], env=env)
        return output

    def summary(self, kubeconfig):
        self.step(f"{self.node} is part of the cluster")
        if kubeconfig:
            say(f"  export KUBECONFIG={kubeconfig}")
            say("  kubectl --context cvp get nodes -o wide")
        say("Next steps:")
        if self.first:
            say("  - Point your public names at this host in Cloudflare (proxied, orange cloud).")
            say("  - Bootstrap Flux: docs/runbooks/cluster.md#bootstrap")
            say("  - Enable backups and run a restore drill before production data: ansible/README.md")
        say("  - Add another host: install Debian on it, then run `task init` again.")
        say(f"  - Store {node_cli.xdg('XDG_CONFIG_HOME', '.config') / 'cvp/keys'} in your secret store.")

    def run(self):
        say(__doc__.splitlines()[0])
        say(RULES)
        self.controller()
        self.choose_node()
        self.describe_host()
        self.trust_host()
        self.prepare_host()
        self.join()
        self.summary(self.kubeconfig())
        return 0


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def call(argv):
    status = node_cli.main(argv)
    if status:
        raise NodeError(f"`{' '.join(argv[:2])}` failed; fix the reported problem and rerun task init")


def parser():
    root = argparse.ArgumentParser(prog="task init --", description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    root.add_argument("--node", help="inventory name (default: server1, then workerN)")
    root.add_argument("--address", help="the host's public IP address")
    root.add_argument("--ssh-port", default="22")
    root.add_argument("--virt", choices=("vm", "lxc", "metal"))
    root.add_argument("--role", choices=("agent", "server"))
    root.add_argument("--mesh-address", help=f"WireGuard address (first host default {FIRST_MESH_ADDRESS})")
    root.add_argument("--host-key-fingerprint", help="SHA256 fingerprint read in the provider console")
    root.add_argument("--login-user", default="root", help="provider login account (non-root uses sudo)")
    root.add_argument("--root-key", help="SSH key for the provider login (default: password)")
    root.add_argument("--ssh-key", help="operator SSH private key (default: ~/.ssh/cvp-ops, created if missing)")
    root.add_argument("--ssh-source", help="SSH source /32 or /128 (default: detected from the host's view)")
    root.add_argument("--tailscale-auth-key-file", help="private file with the Tailscale auth key")
    root.add_argument("--server-confirm", help="the node name, confirming an additional etcd server")
    root.add_argument("--kubeconfig", help="kubeconfig output for the first host (default: ~/.config/cvp/kubeconfig)")
    root.add_argument("--skip-kubeconfig", action="store_true")
    root.add_argument("--inventory", default=str(node_cli.DEFAULT_INVENTORY))
    root.add_argument("--retry-reviewed", action="store_true",
                      help="retry an interrupted join stage after inspecting the hosts")
    root.add_argument("--yes", action="store_true", help="accept detected values and plans without asking")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    if args.ssh_source and not re.fullmatch(r"[0-9A-Fa-f:.]+/[0-9]{1,3}", args.ssh_source):
        print("error: --ssh-source must be an address with a prefix, such as 203.0.113.10/32", file=sys.stderr)
        return 2
    try:
        return Wizard(args).run()
    except (NodeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("\ninterrupted; rerun task init to continue", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
