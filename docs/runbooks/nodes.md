# Nodes: Bootstrap and Grow the Cluster

This is the one procedure for every host: the first one that initializes the
cluster and each one you add later. Every host starts as a freshly installed
Debian system with nothing else on it.

## Network rules

| Path | Carries | Never carries |
| --- | --- | --- |
| Public IP | SSH (TCP `22`) from your listed operator addresses; HTTP(S) `80`/`443` on the ingress node from Cloudflare's published ranges only; the encrypted WireGuard transport (UDP `51820`) between nodes | Kubernetes API, etcd, kubelet, VXLAN |
| WireGuard (`wg0`) | Node-to-node cluster traffic: API `6443`, etcd `2379`/`2380`, kubelet `10250`, Flannel VXLAN `8472` | SSH |
| Tailscale | People (and CI) reaching internal services: Kubernetes API `6443`, internal applications through the ingress node's Traefik | SSH, cluster-internal ports |

The host firewall, the tailnet policy, and the commands below enforce these
rules; there is no "move SSH to Tailscale" step.

## Quick path: `task init`

`task init` runs everything in sections 2–4 for one host, asking only for what
it cannot detect: the host's public IP, the console fingerprint (section 3.1),
and the Tailscale auth key (stored as a `0600` file). It reads the address you
SSH from out of the host's own view of the connection (`$SSH_CONNECTION`) and
asks you to confirm it as the node's permanent SSH source. It then runs
`node-new` (showing the plan first), `node-bootstrap`, `node-join`, and, for the
first host, the kubeconfig export. Rerun it to resume after a failure (add
`--retry-reviewed` once you have inspected an interrupted `site`, section 6) or
to add the next host. The rest of this runbook explains each step and is the
manual path.

## Commands

| Command | What it does | Touches |
| --- | --- | --- |
| `task node-new` | Allocates the mesh address, generates the WireGuard key, writes host vars, inventory groups, and the operator entry, then validates the result. Dry run unless `--write`; rolls back if validation fails. | Controller files only |
| `task node-bootstrap` | Trusts the fresh host's SSH key only if it matches the provider-console fingerprint, copies `scripts/node-bootstrap.sh` to it over SSH, and runs it as root: installs Python, sudo, and SSH, and creates the `ops` operator with your key and passwordless sudo. Then proves `ops` login and sudo. | The new host (accounts and packages only) |
| `task node-join` | Validates, probes, checks fleet membership, converges, probes the mesh, verifies. Records progress and resumes. | The new host and, during `site`, the whole fleet |

Run every command from the root of your **instance repository** (created with
`task new-instance` in the platform repository; see the platform README). Its
pinned platform release (installed from `platform.lock` into `collections/`)
provides these tasks; your inventory, cluster apps, and
Flux entry point live beside it. `example` below stands for your instance
name: per-user files live in `~/.config/cvp/<instance>/`. A new instance's
inventory is empty and creates no machines. Add **one node at a time**.

All public IPs (`203.0.113.*`, `2001:db8::*`), Tailscale addresses, paths, and
fingerprints below are **illustrative; replace them**. The mesh example
`10.77.0.0/24` is RFC1918, but use it only if it is unused in your environment;
never deploy a documentation-only range such as `192.0.2.0/24` as the mesh.

## 1. Prerequisites

On a Debian controller, install the system prerequisites and
[mise](https://mise.jdx.dev/getting-started.html), then run the local checks:

```sh
sudo apt-get update
sudo apt-get install git curl python3 python3-yaml sqlite3 openssl \
  openssh-client openssh-server wireguard-tools
mise install
export CVP_TEST_SSHD=/usr/sbin/sshd
task deps
task test
```

Activate mise for your shell, or prefix Task commands with `mise exec --`.
`task test` needs a real `sshd` binary as a config parser (no daemon is
started). Credential-free checks **are not offline**: tools, collections,
chart assets, schemas, and providers can be downloaded. Existing mise Ansible
installations may need `mise install --force pipx:ansible-core`.

Gather these inputs before the first host:

| Input | What to check |
| --- | --- |
| A host with a public IP | Provider console access; you will install Debian on it (section 3.1) |
| Your public SSH source | The controller's actual public IPv4 `/32` or IPv6 `/128`. It is the **permanent** SSH allowance, so prefer a stable address (office, VPN egress, or bastion) |
| Operator SSH key | Dedicated, passphrase-less automation key outside Git (section 2) |
| Mesh subnet | One unused RFC1918 `/24`; no overlap with your LAN, routes, or K3s pod/service CIDRs |
| Tailscale | Controller enrolled; ACL lets admins reach `tag:k3s` on TCP `6443` and `tag:k3s-ingress` on `80`/`443`; `tagOwners` for `tag:k3s` and `tag:k3s-ingress`; a **node enrollment auth key** for those tags (not a provider API credential) |
| Cloudflare | The public names you will proxy to the ingress node (orange-cloud). Direct, non-Cloudflare requests to the origin are dropped |

If adopting the repository's tailnet policy, follow the
[Tailscale adoption procedure](tofu.md#adopting-external-resources) first: that
root owns the complete ACL and DNS configuration.

In the provider firewall (if any), allow TCP `22` from your SSH source only, UDP
`51820` to every node, and TCP `80`/`443` to the ingress node. Public `6443`,
etcd, kubelet, and VXLAN ports are never needed.

## 2. Create the operator SSH key (once)

```sh
umask 077
mkdir -p "$HOME/.ssh" "$HOME/.config/cvp"
chmod 0700 "$HOME/.ssh" "$HOME/.config/cvp"
ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/cvp-ops" -C cvp-ops
```

`node-bootstrap` installs `cvp-ops.pub` for the `ops` account. Generate keys
once, not on each retry.

## 3. First host

### 3.1 Install Debian from scratch

In the provider panel, install **Debian 13 (trixie), amd64**, minimal, as a VM
or bare metal. Choose the SSH server option if the installer offers one. Either
set a root password or give the provider your root SSH key; both work for the
one-time bootstrap. Note the public IPv4/IPv6 address.

Read the SSH host key fingerprint **through the provider console** (not over
the network), and keep it for `node-bootstrap`:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Example output: `256 SHA256:Xy...Q root@server1 (ED25519)`. If the image has no
SSH server yet, run `apt-get install -y openssh-server` in the console first.
Cloud images that allow only a sudo user (such as `admin` or `debian`) are
supported with `--login-user`.

LXC containers additionally need provider-supplied overlay/VXLAN/bridge-netfilter
support, delegated cgroups, TUN access, and bridge sysctls; a failing probe
calls for provider changes or a VM.

### 3.2 Scaffold it

Paste the Tailscale enrollment key from your secret store into a private file
(it is not echoed or kept in shell history), then preview the node:

```sh
mkdir -p -m 0700 "$HOME/.config/cvp/example/keys"
(umask 077 && read -rs key && printf '%s\n' "$key" > "$HOME/.config/cvp/example/keys/server1.ts-authkey")
task node-new -- server1 --ssh 203.0.113.20 --virt vm \
  --mesh-address 10.77.0.1 --ssh-key "$HOME/.ssh/cvp-ops" \
  --ssh-source 203.0.113.10/32 \
  --tailscale-auth-key-file "$HOME/.config/cvp/example/keys/server1.ts-authkey"
```

Review the printed plan, then rerun the same command with `--write`. The first
node is always the cluster-init server, the designated API server, and the sole
ingress node; it gets directory-backed local storage on the root filesystem
(no formatting). The command writes:

- `inventory/hosts.yml`: group membership and both shared server selections;
- `inventory/host_vars/server1.yml`: identity, mesh, labels, storage;
- `~/.config/cvp/example/keys/server1.wg-private` (mode `0600`): a new WireGuard key;
- `~/.config/cvp/example/operator.yml` (mode `0600`): credential references and your SSH source.

**Store the WireGuard private key in your external secret store now.** The
generated files are shown in [section 8](#8-reference-generated-files). Pass
`--label key=value` (repeatable) to replace the default tags, `--endpoint` for
a WireGuard endpoint different from the SSH address, and `--no-storage` to skip
storage preparation. Edit the generated host vars before joining for anything
else, such as a custom SSH port.

### 3.3 Bootstrap the fresh host

```sh
task node-bootstrap -- server1 --confirm server1 \
  --host-key-fingerprint SHA256:REPLACE_WITH_CONSOLE_FINGERPRINT
```

It refuses to continue unless the host presents the key you read in the
console, then asks for the root password once (or uses `--root-key`). It copies
`scripts/node-bootstrap.sh` to the host, runs it as root, deletes it, and
proves that `ops` logs in with your operator key and has passwordless sudo. The
script installs `python3`, `python3-apt`, `sudo`, `kmod`, `procps`, and
`openssh-server`; it does not touch networking. For a sudo-only cloud image use
`--login-user admin` (the script then runs with `sudo`).

### 3.4 Join it

Preview first, then join:

```sh
task node-join -- server1 --confirm server1 --preview
task node-join -- server1 --confirm server1
```

Expected: `Join verified for server1.` The preview runs inventory validation,
the read-only probe, and a check-mode `site` diff; check mode does not
exchange tokens or start services. The real run continues with `site`, which
enrolls Tailscale, brings up WireGuard and the firewall, and installs K3s. The
node registers quarantined; its labels/taints are applied and the quarantine
removed in one API patch. From now on SSH is accepted only from your listed
public source, and the API certificate covers the server's Tailscale address.

### 3.5 Export a kubeconfig over Tailscale

Read the server's Tailscale address and export a TLS-verified kubeconfig that
reaches the API through the tailnet:

```sh
ssh -i "$HOME/.ssh/cvp-ops" ops@203.0.113.20 tailscale ip -4
CVP_KUBECONFIG_HOST=server1 CVP_KUBECONFIG_CONFIRM=server1 \
CVP_KUBECONFIG_CONTEXT=cvp \
CVP_KUBECONFIG_SERVER=https://100.100.100.20:6443 \
CVP_KUBECONFIG_OUTPUT="$HOME/.config/cvp/example/kubeconfig" \
  task export-kubeconfig
export KUBECONFIG="$HOME/.config/cvp/example/kubeconfig"
mise exec -- kubectl --context cvp get --raw=/readyz
mise exec -- kubectl --context cvp get nodes -o wide
```

Choose a **new** output path outside Git. The exported credentials are
cluster-admin secrets. Never use `insecure-skip-tls-verify` to bypass a SAN,
CA, routing, or ACL failure. Expected: `/readyz` returns `ok` and `server1` is
Ready with InternalIP `10.77.0.1`. Optionally record the address as
`tailscale_address` in its host vars. **Flux is a separate step:** continue
with [the cluster runbook](cluster.md#bootstrap) and [external providers](tofu.md).

### 3.6 Accept the host and establish recovery before production

- Record probe/verify results, SSH and API access, and an intentional reboot
  check. Local tests do not prove production reboot, network, or recovery
  behavior.
- Point the public names at the ingress node through Cloudflare (proxied).
  Direct requests to the origin from non-Cloudflare addresses are dropped.
- Before production data, enable encrypted off-host backups following
  [backup enablement](../../ansible/README.md#backup-enablement), and perform a
  [disposable restore drill](../../ansible/README.md#datastore-restore).
  Datastore recovery does not back up application volume data.
- A single host is not highly available.

## 4. Add another host

### 4.1 Confirm the fleet is ready

```sh
task verify
```

Every existing node must be Ready, non-terminating, and match its role and
WireGuard InternalIP. Review placement and recovery impact: adding nodes does
not make ingress or local data highly available. Keep exactly one ingress node;
move it only with [ingress relocation](ingress-relocation.md).

### 4.2 Install Debian, scaffold, and bootstrap it

Install Debian and read its fingerprint as in [section 3.1](#31-install-debian-from-scratch), then:

```sh
task node-new -- worker1 --ssh 203.0.113.21 --virt vm \
  --ssh-source 203.0.113.10/32 \
  --tailscale-auth-key-file "$HOME/.config/cvp/example/keys/worker1.ts-authkey"
task node-bootstrap -- worker1 --confirm worker1 \
  --host-key-fingerprint SHA256:REPLACE_WITH_CONSOLE_FINGERPRINT
```

Run `node-new` once without `--write` to review, then with it. Later nodes
default to compute-only agents with the next free mesh address and the operator
key shared by the existing nodes. Use `--mesh-address`, `--label`, `--storage`,
and `--role server` to change that. The operator file must still resolve
**every** credential reference for **every** host on each run (section 8).

### 4.3 Join it

```sh
task node-join -- worker1 --confirm worker1
```

`site` converges **the entire fleet**, because every existing peer needs the new
WireGuard key and route. The membership preflight first requires the
initialized API to be ready and every other inventory node to be Ready with its
expected role and address; only the joining node may be absent.

**Another server** changes etcd quorum. Two servers tolerate no server failure;
three tolerate one. Prefer a planned three-server topology and join one at a
time. SQLite permits only one server. Confirm the quorum review explicitly:

```sh
task node-new -- server2 --ssh 203.0.113.22 --virt vm --role server \
  --ssh-source 203.0.113.10/32 \
  --tailscale-auth-key-file "$HOME/.config/cvp/example/keys/server2.ts-authkey"
task node-bootstrap -- server2 --confirm server2 \
  --host-key-fingerprint SHA256:REPLACE_WITH_CONSOLE_FINGERPRINT
task node-join -- server2 --confirm server2 --server-confirm server2
```

Never add a second init server, reset the datastore, or point the shared server
selections at a node that has not joined.

### 4.4 Accept it

```sh
task probe-wireguard
mise exec -- kubectl --context cvp get nodes -o wide
```

Record live handshakes and path MTU, run large cross-node TCP and UDP transfers
before relying on the default `1420` WireGuard / `1370` pod MTU, and test
placement and reboot. A `--limit`ed `task verify` checks only the selected
nodes; it is not fleet acceptance. Removing a label affects new scheduling only;
it does not evict existing pods.

## 5. How `node-join` runs

| Stage | Kind | Result |
| --- | --- | --- |
| `validate` | read-only | Effective inventory, topology, and node tags are valid (controller only) |
| `access` | mutating | `ops` login and sudo work; if not, run `task node-bootstrap` (or pass `--root-key` to use the Ansible `prepare-access` path) |
| `probe` | read-only | Host compatibility (kernel, cgroups, modules, virtualization) |
| `preflight` | read-only | Later nodes only: API `/readyz` and full fleet membership |
| `site` | mutating | Full-fleet convergence under lifecycle locks; the node joins |
| `mesh` | read-only | The node's WireGuard peers and no-fragment path MTU |
| `verify` | read-only | Every host and cluster node |

Progress lives in `~/.local/state/cvp/example/nodes/` (`$XDG_STATE_HOME`). Rerunning the
same command after a failure skips the stages before the last **completed
mutating** stage and reruns the read-only checks after it on fresh state. If a
mutating stage was **interrupted**, the command refuses to retry it until you
have inspected the hosts (section 6) and pass `--retry-reviewed`. Any change to
the resolved inventory or operator configuration invalidates completed stages.
`--restart` ignores recorded progress.

The run pins the operator file and every credential file it references. Do not
edit, create, or remove them during a run: the next stage stops.

## 6. If a stage fails

| Failed stage | What to do before continuing |
| --- | --- |
| `node-new` | Nothing was kept. Fix the reported inventory, credential, or address problem |
| `node-bootstrap` host key | Stop. Re-read the fingerprint in the provider console; never bypass the check |
| `node-bootstrap` script | Read its output; it is safe to rerun. It changes only packages, the `ops` account, its key, and `/etc/sudoers.d/ops` |
| `validate`, `probe`, `preflight` | Fix tools, inventory, secrets, sudo, compatibility, or fleet health. These gates do not mutate hosts or take locks |
| `site` | Later phases stop and acquired `/var/lib/cvp/lifecycle.lock` directories can remain across the fleet. Inspect every selected host's lock owner, running controller/host processes, and service journals. Resolve the interrupted state before explicit lock cleanup, then rerun with `--retry-reviewed` |
| `mesh`, `verify` | The join may be complete and locks released. Diagnose live state, then rerun to resume. Do not delete the Node or reset etcd to hide an error |

Locks never expire and are never stolen automatically. If a restore guard or
staging exists, follow [datastore recovery](../../ansible/README.md#datastore-restore)
before any cleanup or startup; deleting a guard can authorize startup of an
unresolved datastore.

### Your public SSH address changed

SSH is accepted only from the sources in each host's operator entry. Before
your address changes, add the new `/32` or `/128` next to the old one in every
host's `firewall_ssh_ipv4_source_cidrs` (or `..._ipv6_...`) and run
`task site`; remove the old one afterwards. If you are already locked out, open
the provider console on each host and temporarily allow the new source, then
fix the operator file and converge:

```sh
nft insert rule inet cvp_filter input ip saddr 198.51.100.7 tcp dport 22 accept
```

`task site` replaces that temporary console rule with the managed policy.

## 7. Removing a node

Removal is a separate reviewed operation. Relocate ingress if applicable,
preserve affected local data, and review quorum and backups. Then drain the
node and delete it with the explicit cluster context. K3s removes a deleted
server's etcd member; verify the remaining quorum before cleaning up the host.
Stop and remove the repository-managed K3s installation (there is no
installer-created uninstall script), remove the node's host vars, inventory
groups, operator entry, and key files together, and run `task site` to remove
its WireGuard peer. Replacing the init or designated API server is a
coordinated topology and recovery change, not an inventory edit.

## 8. Reference: generated files

After `server1` and `worker1`, `inventory/hosts.yml` is:

```yaml
---
all:
  vars:
    k3s_cluster_init_host: server1
    k3s_server_host: server1
  children:
    wireguard:
      hosts:
        server1: {}
        worker1: {}
    k3s_servers:
      hosts:
        server1: {}
    k3s_agents:
      hosts:
        worker1: {}
    storage_stateful:
      hosts: {}
    ingress:
      hosts:
        server1: {}
```

Both server selections stay in `all.vars` so every node inherits them.
Connection and mesh settings (`ansible_user: ops`, `wg0`, UDP `51820`) are
platform defaults in the installed collection's
`ansible/defaults/group_vars/all.yml` (see `platform.lock` for the release).
Override a
platform default in the instance's `inventory/group_vars/all.yml`, which
outranks both the platform defaults and `all.vars`; it must not override the
server selections. Every mesh host is in exactly one of `k3s_servers` and
`k3s_agents`, matching its `k3s_role`.

`host_vars/server1.yml`:

```yaml
---
ansible_host: "203.0.113.20"
ansible_port: 22
ansible_private_key_file: "/home/operator/.ssh/cvp-ops"
node_name: server1
node_virtualization: vm
wireguard_address: "10.77.0.1"
wireguard_endpoint: "203.0.113.20:51820"
wireguard_public_key: "REPLACE_WITH_SERVER1_WG_PUBLIC_KEY"
tailscale_address: ""
tailscale_advertise_tags: ["tag:k3s", "tag:k3s-ingress"]
k3s_role: server
k3s_server_init: true
k3s_tls_sans: []
k3s_node_labels:
  - cvp.novirmor.io/compute=true
  - cvp.novirmor.io/storage=true
  - cvp.novirmor.io/system=true
  - cvp.novirmor.io/ingress=true
  - svccontroller.k3s.cattle.io/enablelb=true
  - svccontroller.k3s.cattle.io/lbpool=public
k3s_node_taints: []
storage_enabled: true
storage_device: ""
storage_mountpoint: /var/lib/rancher/k3s/storage
storage_manage_device: false
storage_allow_format: false
```

`host_vars/worker1.yml`:

```yaml
---
ansible_host: "203.0.113.21"
ansible_port: 22
ansible_private_key_file: "/home/operator/.ssh/cvp-ops"
node_name: worker1
node_virtualization: vm
wireguard_address: "10.77.0.2"
wireguard_endpoint: "203.0.113.21:51820"
wireguard_public_key: "REPLACE_WITH_WORKER1_WG_PUBLIC_KEY"
tailscale_address: ""
tailscale_advertise_tags: ["tag:k3s"]
k3s_role: agent
k3s_server_init: false
k3s_tls_sans: []
k3s_node_labels:
  - cvp.novirmor.io/compute=true
k3s_node_taints: []
storage_enabled: false
storage_device: ""
storage_manage_device: false
storage_allow_format: false
```

The ingress node must declare all three ingress labels; other nodes must omit
the ServiceLB labels. `cvp.novirmor.io/role` is derived from `k3s_role`; do not declare
it. Custom label domains must first be added to `k3s_managed_label_domains`
(see [the host layer guide](../../ansible/README.md#inventory-inputs)).
`storage_enabled: false` skips host storage preparation; it does not disable
K3s's local-path provisioner. Device-backed storage and formatting go through
the [storage gate](../../ansible/README.md#controlled-bootstrap). For a custom
SSH port, align `ansible_port`, `base_ssh_port`, `firewall_ssh_port`, the host
listener, the provider firewall, and the tailnet ACL **before** joining.

`~/.config/cvp/example/operator.yml` (mode `0600`, outside Git):

```yaml
---
cvp_operator_defaults: {}
cvp_operator_hosts:
  server1:
    wireguard_private_key:
      file: /home/operator/.config/cvp/example/keys/server1.wg-private
    tailscale_auth_key:
      file: /home/operator/.config/cvp/example/keys/server1.ts-authkey
    firewall_ssh_ipv4_source_cidrs:
    - 203.0.113.10/32
    firewall_ssh_ipv6_source_cidrs: []
  worker1:
    wireguard_private_key:
      file: /home/operator/.config/cvp/example/keys/worker1.wg-private
    tailscale_auth_key:
      file: /home/operator/.config/cvp/example/keys/worker1.ts-authkey
    firewall_ssh_ipv4_source_cidrs:
    - 203.0.113.10/32
    firewall_ssh_ipv6_source_cidrs: []
```

Credentials (`wireguard_private_key`, `tailscale_auth_key`) are literal strings,
`{file: /absolute/path}` references to a private (`0600`, owned by you) file
outside the checkout, or `{env: NAME}` references. **Every reference resolves
on every invocation**, including other hosts'. After enrollment and key
persistence are verified you may remove a host's references and rely on the
host's existing Tailscale state and persisted WireGuard key; never leave a
dangling reference. No Jinja or other environment references are evaluated.
Private keys, enrollment keys, and destructive approvals belong here;
connection identity, mesh public keys, and roles belong in inventory. See the
full [operator schema](../../ansible/README.md#inventory-inputs).

### Manual equivalents

The commands only orchestrate existing guarded tasks. `task validate-inventory`,
`task prepare-access`, `task probe -- --limit NODE`, `task site`,
`task probe-wireguard`, and `task verify` remain available for diagnosis. `task
onboard` (`CVP_ONBOARD_NODE`, `CVP_ONBOARD_CONFIRM`, optional
`CVP_ONBOARD_SERVER_CONFIRM`) is an alias for `node-join` on an existing
cluster. Later mutating `--limit` selections must include both the init server
and the designated API server; `site` validates the whole inventory even when
limited.
