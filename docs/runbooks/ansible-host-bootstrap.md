# First Host: “I Have a Host; What Next?”

Start here with **one existing host**. This procedure turns it into `server1`,
the initial K3s server and the sole ingress node, then gives your controller a
TLS-verified private kubeconfig. Add later hosts with
[node-onboarding.md](node-onboarding.md) after this procedure succeeds.

Run controller commands from the repository root. The default inventory is
empty and creates no machines. Use `task site` for initial bootstrap;
`task onboard` requires an already initialized control plane.

## 1. Check the host and controller prerequisites

**Recommended starting point:** a fresh Debian 13 (trixie), amd64 VM with
systemd, working package repositories, and provider-console access. This is a
dependency-compatible baseline, not a claim of a completed live deployment
test. Hosts need `python3-kubernetes >= 24.2` and `python3-jsonpatch`; convergence
installs them from the host's package repositories. Review the pinned K3s
version in `ansible/inventory/group_vars/all.yml` before deployment.

Pin `node_virtualization` to `vm`, `metal`, or `lxc`. LXC is conditional on
provider-supplied overlay/VXLAN/bridge-netfilter support, delegated cgroups,
TUN access, and bridge sysctls. The guest cannot load host kernel modules.
A failed LXC compatibility probe calls for provider changes or a VM.

On a Debian controller, install these system prerequisites, in addition to
[mise](https://mise.jdx.dev/getting-started.html):

```sh
sudo apt-get update
sudo apt-get install git curl python3 python3-yaml sqlite3 openssl \
  openssh-client openssh-server wireguard-tools
mise install
```

Activate mise for your shell so `task` is available, or prefix Task commands
with `mise exec --`. Install the collections and run the local checks:

```sh
export CVP_TEST_SSHD=/usr/sbin/sshd
task deps
task test
```

`ssh-keygen` and a real `sshd` parser are required by the tests; the parser test
does not start a daemon. Existing mise Ansible installations may need
`mise install --force pipx:ansible-core` to pick up the pinned JSON dependencies.
Credential-free tests **are not necessarily offline**: tool installation,
collections, chart assets, schemas, and OpenTofu providers can require downloads.
The optional unprivileged network-namespace integration checks and their extra
kernel/tool prerequisites are listed in [README.md](../../README.md#development).

Before continuing, gather these inputs:

| Input | Where it belongs / what to check |
| --- | --- |
| SSH endpoint, host fingerprint, initial root key | Provider console and controller `known_hosts`; root login must already work |
| Operator SSH key | Private key outside Git; public key in a one-line file; persistent private-key path in inventory |
| Public WireGuard endpoint | Stable DNS/IP plus UDP `51820`; independent of the SSH endpoint |
| Mesh subnet | One unused RFC1918 `/24`, unique bare IPv4 addresses; no overlap with your LAN, routes, or K3s pod/service CIDRs |
| Tailscale enrollment | Existing tailnet, controller already enrolled, administrator access and reviewed ACL/tag ownership |
| Temporary public SSH source | Controller's actual public egress IPv4 `/32` and/or IPv6 `/128`, host-scoped |
| Storage intent | This first-host example uses a directory on the root filesystem; no disk formatting |

The tailnet must permit your controller identity to reach `tag:k3s` on TCP
`22` and `6443`. Define `tagOwners` for `tag:k3s` and `tag:k3s-ingress`, and
create a **node enrollment auth key authorized for the advertised tags**.
This auth key is distinct from a Tailscale provider API/OAuth credential.
If adopting the repository's OpenTofu policy, follow the
[Tailscale adoption procedure](tofu.md#adopting-external-resources): that root
owns the complete ACL and DNS configuration, so review/import the existing
policy before applying it.

Provider firewalls must allow bootstrap SSH from that same narrow controller
source and UDP `51820` to the public WireGuard endpoint. Permit public TCP
`80`/`443` only if public ingress is intended. Public `6443`, etcd, and VXLAN
ports are not needed: cluster traffic uses WireGuard and administration uses
Tailscale. Allow the outbound connectivity needed for packages and Tailscale.

All public IPs below (`203.0.113.*`), private Tailscale example addresses, paths,
and key placeholders are **illustrative; replace them**. The mesh example
`10.77.0.0/24` is RFC1918, but use it only if it is unused in your environment.
Do not deploy a documentation-only subnet such as `192.0.2.0/24` as your mesh.

## 2. Prepare keys and trust the bootstrap SSH host

Create a dedicated operator automation key outside this checkout if you do not
already have one. The explicit-identity commands below require a key usable
without a passphrase prompt: `prepare-access` disables agent use in that mode.
Protect the key and its parent directory with private filesystem permissions:

```sh
umask 077
mkdir -p "$HOME/.ssh" "$HOME/.config/cvp"
chmod 0700 "$HOME/.ssh" "$HOME/.config/cvp"
ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/cvp-ops" -C cvp-ops
wg genkey > "$HOME/.config/cvp/server1.wg-private"
wg pubkey < "$HOME/.config/cvp/server1.wg-private" > "$HOME/.config/cvp/server1.wg-public"
```

Generate keys once, not on each retry. Keep the WireGuard private key in your
external secrets store; only its public key enters inventory. The `.pub` file
from `ssh-keygen` is the one-line public key used by `prepare-access`.

Obtain the SSH host fingerprint through the provider console or another trusted
provider channel. Collect the presented key **read-only** and compare:

```sh
ssh-keyscan -p 22 -t ed25519 203.0.113.20 > "$HOME/.config/cvp/server1.bootstrap-hostkey"
ssh-keygen -lf "$HOME/.config/cvp/server1.bootstrap-hostkey"
```

`ssh-keyscan` does not authenticate the host. **Only after the fingerprint
matches** the trusted provider fingerprint, add the collected key and test root
access (replace the provider key path):

```sh
cat "$HOME/.config/cvp/server1.bootstrap-hostkey" >> "$HOME/.ssh/known_hosts"
ssh -F /dev/null -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes \
  -i "$HOME/.ssh/provider-root" -p 22 root@203.0.113.20 'id -un'
```

Expected: `root`. If the provider supplies only a non-root account, **stop** and
use its console/recovery procedure to install your approved root public key
and establish key-authenticated root SSH. `prepare-access` cannot create the
initial connection. Do not bypass fingerprint checking or enable password root
login to get past this prerequisite.

## 3. Configure the complete one-host inventory

Use this complete minimal `ansible/inventory/hosts.yml`:

```yaml
---
all:
  vars:
    ansible_user: ops
    ansible_become: true
    wireguard_interface: wg0
    wireguard_port: 51820
    wireguard_peers_group: wireguard
    k3s_cluster_init_host: server1
    k3s_server_host: server1
  children:
    wireguard:
      hosts:
        server1: {}
    k3s_servers:
      hosts:
        server1: {}
    k3s_agents:
      hosts: {}
    storage_stateful:
      hosts: {}
    ingress:
      hosts:
        server1: {}
```

Keep **both server selections in `all.vars`**, so later hosts inherit the same
values. Role defaults remain empty until you explicitly select a host. Ansible
`group_vars/all.yml` takes precedence over inventory `all.vars`: shared group
vars must not contain a conflicting/empty `k3s_cluster_init_host` assignment.
Check the effective values with the commands below before host access.

Create `ansible/inventory/host_vars/server1.yml` (the existing
`example-newnode.yml.example` is a reference, not a loaded inventory file):

```yaml
---
ansible_host: "203.0.113.20"      # bootstrap SSH endpoint; later change to Tailscale
ansible_port: 22
ansible_private_key_file: "/home/operator/.ssh/cvp-ops"  # replace with your absolute path
node_name: server1
node_virtualization: vm

wireguard_address: "10.77.0.1"    # bare IP, not /24; all peers use this same /24
wireguard_endpoint: "203.0.113.20:51820"
wireguard_public_key: "REPLACE_WITH_SERVER1_WG_PUBLIC_KEY"

tailscale_address: ""            # record the assigned address after enrollment
tailscale_advertise_tags: [tag:k3s, tag:k3s-ingress]
k3s_role: server
k3s_server_init: true
k3s_tls_sans: []                 # add private API IP/DNS before kubeconfig export
k3s_node_labels:
  - cvp.io/compute=true
  - cvp.io/storage=true
  - cvp.io/system=true
  - cvp.io/ingress=true
  - svccontroller.k3s.cattle.io/enablelb=true
  - svccontroller.k3s.cattle.io/lbpool=public
k3s_node_taints: []

storage_enabled: true
storage_device: ""
storage_mountpoint: /var/lib/rancher/k3s/storage
storage_manage_device: false
storage_allow_format: false
```

For a public IPv6 WireGuard endpoint, use brackets:
`"[2001:db8::20]:51820"` (replace the documentation address). The WireGuard
endpoint stays public/stable even when the SSH endpoint becomes private.

The defaults are TCP `22` for SSH, UDP `51820` for WireGuard, embedded **etcd**,
amd64 K3s, and `/var/lib/rancher/k3s/storage` for local-path data. If using a
custom SSH port, align `ansible_port`, `base_ssh_port`, `firewall_ssh_port`, and
the actual host listener **before** convergence; update provider firewall and
tailnet ACL ports too. The supplied tailnet ACL assumes port `22`.

This directory-backed storage uses the root filesystem and does not format a
device. It provides neither replicated data nor an off-host backup; we have not
declared `cvp.io/stateful=true` or enrolled the host in `storage_stateful`.
Storage-enabled nodes must all use the fleet's shared
`k3s_default_local_storage_path`. Use the
[storage gate](../../ansible/README.md#controlled-bootstrap) before introducing
device-backed storage or formatting approvals.

The initial topology requires exactly one ingress node, with all three ingress
labels above for the later Traefik/ServiceLB configuration. `cvp.io/role` is
derived from `k3s_role`; do not declare it. A single host is not HA.

## 4. Create persistent, host-scoped operator settings

Create `$HOME/.config/cvp/operator.yml` in your editor, outside Git:

```yaml
---
cvp_operator_defaults: {}
cvp_operator_hosts:
  server1:
    wireguard_private_key: {env: SERVER1_WG_PRIVATE_KEY}
    tailscale_auth_key: {env: SERVER1_TAILSCALE_AUTH_KEY}
    firewall_ssh_ipv4_source_cidrs: ["203.0.113.10/32"]
    firewall_ssh_ipv6_source_cidrs: []
```

Replace `203.0.113.10/32` with your controller's **actual public egress IP**;
for IPv6 use its `/128` in the IPv6 list. Do not use `0.0.0.0/0` or `::/0` for
SSH. Keep this exception on `server1`, not in fleet-wide defaults.

```sh
chmod 0600 "$HOME/.config/cvp/operator.yml"
export CVP_OPERATOR_CONFIG_FILE="$HOME/.config/cvp/operator.yml"
export SERVER1_WG_PRIVATE_KEY="$(cat "$HOME/.config/cvp/server1.wg-private")"
```

Load `SERVER1_TAILSCALE_AUTH_KEY` into the environment from your external secret
manager without putting the value in shell history. Both credentials also
accept literal single-line strings in this private file. No Jinja evaluation
or arbitrary environment references are supported. Private keys, enrollment
keys, and destructive approvals belong in `cvp_operator_hosts`; connection
identity, mesh public keys, and roles belong in inventory. See the full
[operator schema](../../ansible/README.md#inventory-inputs).

**Every loader invocation resolves every configured environment reference**,
including references for other hosts. Keep referenced secrets available for
site, probe, verify, and onboarding. After enrollment/persistence is verified,
you may remove the enrollment reference and rely on the host's existing
Tailscale state; likewise, a verified persisted WireGuard key can be reused
without a supplied key. Alternatively keep literal credentials in the private
file. Do not leave dangling references and assume later read-only tasks ignore
them. Preserve recoverable keys in your external secrets store.

## 5. Validate, prepare access, and probe

```sh
task validate-inventory
ANSIBLE_CONFIG=ansible/ansible.cfg mise exec -- ansible-inventory \
  -i ansible/inventory/hosts.yml --host server1
```

Expected: valid one-host topology; both `k3s_cluster_init_host` and
`k3s_server_host` resolve to `server1`. The inventory validator is controller-only
and read-only. An empty selection, duplicate key/address, incorrect group/role,
or storage-path mismatch must be fixed before continuing.

Now grant `ops` access using the previously trusted root connection:

```sh
CVP_ACCESS_NODE=server1 CVP_ACCESS_CONFIRM=server1 \
CVP_ACCESS_PUBLIC_KEY_FILE="$HOME/.ssh/cvp-ops.pub" \
CVP_ACCESS_ROOT_IDENTITY_FILE="$HOME/.ssh/provider-root" \
CVP_ACCESS_OPERATOR_IDENTITY_FILE="$HOME/.ssh/cvp-ops" \
  task prepare-access
task probe -- --limit server1
task site -- --check --diff
```

Expected: operator login and passwordless sudo verified; compatibility probe
passes; review the check-mode changes. `prepare-access` installs only Python,
sudo, and probe prerequisites and creates `ops`; it does not change the firewall,
WireGuard, or K3s. Its `CVP_ACCESS_*` identity settings apply **only to that
invocation**; the inventory `ansible_private_key_file` keeps later tasks using
the same operator key. Both explicit access keys (provider root and operator)
must be usable noninteractively. They use strict host-key checking and ignore
SSH config/agent fallback, so endpoint and port must be in inventory.

`task probe` installs nothing and does not require WireGuard yet. Stop for
missing host packages/kernel facilities or a virtualization mismatch. Site
check mode previews changes; it does not exchange tokens, activate services,
or prove that a fresh machine will start successfully.

## 6. Converge the first host

```sh
task site
```

Expected: base packages/settings, Tailscale enrollment, WireGuard, firewall,
storage directory, and K3s converge; `server1` becomes Ready with InternalIP
`10.77.0.1`. Site registers the node quarantined, then applies desired
labels/taints and removes the reserved bootstrap quarantine in one API patch.
Successful site completion releases `/var/lib/cvp/lifecycle.lock`.

For one host, use the full inventory. Later mutating `--limit` selections must
include both the init server and designated API/token server to lock their
shared dependencies (the same `server1` in this example). Site validates the
whole inventory even when limited. A failure stops subsequent phases and can
retain acquired lifecycle locks; use the failure table below before retrying.

## 7. Move SSH to the private address before closing public SSH

Keep the temporary public SSH exception while proving the private path. Read
the assigned address through the trusted connection:

```sh
ssh -F /dev/null -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes \
  -i "$HOME/.ssh/cvp-ops" -p 22 ops@203.0.113.20 'tailscale ip -4'
```

Suppose it returns `100.100.100.20`; replace that example everywhere below.
Collect the host key at the private address, compare it with the same trusted
host fingerprint from stage 2, and **only after a match** add it to known hosts:

```sh
ssh-keyscan -p 22 -t ed25519 100.100.100.20 > "$HOME/.config/cvp/server1.private-hostkey"
ssh-keygen -lf "$HOME/.config/cvp/server1.private-hostkey"
# After comparing with the trusted server1 fingerprint:
cat "$HOME/.config/cvp/server1.private-hostkey" >> "$HOME/.ssh/known_hosts"
ssh -F /dev/null -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes \
  -o ControlMaster=no -o ControlPath=none \
  -i "$HOME/.ssh/cvp-ops" -p 22 ops@100.100.100.20 'sudo -n true'
```

Expected: a **fresh** private SSH login and noninteractive sudo both succeed.
Tailscale backend state `Running` alone is not proof of ACL/listener/firewall
access. If this fails, retain the public exception and resolve the private path.

Change `ansible_host` in `host_vars/server1.yml` to the assigned Tailscale IP
and record it in `tailscale_address`. Prove Ansible uses that path:

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg mise exec -- ansible \
  -i ansible/inventory/hosts.yml server1 -m ansible.builtin.command \
  -a 'id -un' --become
task probe -- --limit server1
```

Expected: `root` from Ansible and a passing probe over private SSH. Stock sshd
sockets are normally **unbound to a network interface**, even over Tailscale.
Firewall preflight will therefore reject empty SSH source allowlists: backend
`Running`, a private destination IP, and a fresh login are insufficient to prove
the incoming interface. CIDR-less approval requires the exact established socket
to be kernel-bound to `tailscale0` (or the configured WireGuard interface), with
a direct matching return route. The role installs `iproute2` before this guard.

For ordinary Tailscale operators, read the actual client source through the
fresh private connection:

```sh
ssh -F /dev/null -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes \
  -o ControlMaster=no -o ControlPath=none \
  -i "$HOME/.ssh/cvp-ops" -p 22 ops@100.100.100.20 'printf "%s\n" "$SSH_CONNECTION"'
```

The first field is the client source seen by the host. In the existing
`server1` operator entry, replace the public egress CIDR with **that client's
Tailscale IP** as a `/32` (or `/128` in `firewall_ssh_ipv6_source_cidrs` for IPv6),
preserving the other settings and credentials. For example, if the first field
is `100.100.100.10`, use `firewall_ssh_ipv4_source_cidrs: ["100.100.100.10/32"]`.
Keep this explicit private source allowance for later convergence with stock
sshd; do not set both lists to `[]`. If the session fields are unavailable, supply
an independently verified source CIDR; Tailscale backend state cannot substitute
for it. Preflight reports that limited proof explicitly.

With the matching private source CIDR in the same operator file, reconverge and
verify:

```sh
task site
task probe-wireguard
task verify
```

Remove the matching provider-firewall public SSH exception after private
access still succeeds. Keep the public WireGuard endpoint and its UDP rule.
With a single host there are no remote peers/handshakes to test; the mesh probe
and verification are not evidence of cross-node traffic yet.

## 8. Export a private, TLS-verified kubeconfig

In `host_vars/server1.yml`, set `k3s_tls_sans` to include the exact private
API address (or resolvable private DNS name) you will use:

```yaml
k3s_tls_sans: ["100.100.100.20"]
```

Reconverge before exporting; the certificate must cover that endpoint:

```sh
task site
task verify
CVP_KUBECONFIG_HOST=server1 CVP_KUBECONFIG_CONFIRM=server1 \
CVP_KUBECONFIG_CONTEXT=cvp \
CVP_KUBECONFIG_SERVER=https://100.100.100.20:6443 \
CVP_KUBECONFIG_OUTPUT="$HOME/.config/cvp/kubeconfig-server1" \
  task export-kubeconfig
export KUBECONFIG="$HOME/.config/cvp/kubeconfig-server1"
mise exec -- kubectl --context cvp get --raw=/readyz
mise exec -- kubectl --context cvp get nodes -o wide
mise exec -- kubectl --context cvp -n kube-system get deployments,services,pods
```

Choose a **new absolute output path outside Git** in an operator-owned private
directory. The helper captures the root-admin kubeconfig over trusted SSH,
renames the context, sets the explicit endpoint, and checks the API with CA/TLS
verification. Treat the exported client credentials as cluster-admin secrets;
do not commit, share, or paste the file. Do not use `insecure-skip-tls-verify`
to bypass a SAN, CA, routing, or ACL failure.

Expected: `/readyz` returns `ok`; `server1` is Ready with its WireGuard
InternalIP; CoreDNS, packaged Traefik, and ServiceLB are available. **Flux is
still a separate step.** Follow [the cluster runbook](cluster.md#bootstrap)
with this kubeconfig/context for repository/deploy-key/SOPS configuration and
Flux bootstrap. Review ingress placement and public DNS through that runbook
and [the external-provider runbook](tofu.md).

## 9. Accept the host and establish recovery before production

- Record probe/verify results, private SSH/API access, live firewall/service
  activation evidence, and an intentional reboot check. Local tests do not
  establish production reboot/network/recovery behavior.
- Before production data, persist backup enablement, an age recipient, and an
  off-host upload command following
  [backup enablement](../../ansible/README.md#backup-enablement). Upload both
  the encrypted archive and checksum; defaults leave backups disabled.
- Perform a [disposable restore drill](../../ansible/README.md#datastore-restore)
  with `task restore-k3s` before relying on backups. Datastore recovery does not
  replace a backup plan for local application volume data.
- Add subsequent nodes with [node-onboarding.md](node-onboarding.md). Once
  multiple nodes exist, test large cross-node TCP and UDP transfers before
  accepting the default `1420` WireGuard / `1370` pod MTU assumptions.

## If a stage fails

| Failed stage | What to inspect before continuing |
| --- | --- |
| Controller tests / inventory validation | Fix tools, downloads, effective variable precedence, or topology; these stages do not mutate hosts |
| Fingerprint / root login | Stop at provider console/identity verification; no trust bypass |
| `prepare-access` | Inspect partial package/account/key changes; it does not acquire lifecycle locks or change networking |
| Probe / site check mode | Resolve compatibility, sudo, settings, or existing lock availability; check mode does not prove service startup |
| Mutating `site` | Inspect every selected host's `/var/lib/cvp/lifecycle.lock` owner, controller/host processes, and service journals; acquired locks can remain even after partial lock acquisition |
| Private SSH migration | Retain the bootstrap CIDR; confirm controller tailnet, tag/ACL permissions, host fingerprint, listener and firewall ports before changing/removing access |
| Mesh / verification / kubeconfig export after successful site | Diagnose the reported live state; successful site normally already released its locks, and a failed read-only check does not call for a datastore reset |

Do not blindly rerun a failed mutating operation or delete its lock to proceed.
Locks have no automatic expiry or stealing. Explicit cleanup is allowed only
after proving no owner is running and resolving the interrupted state on each
affected host. If a restore guard or staging exists, follow the
[recovery procedure](../../ansible/README.md#datastore-restore); deleting a guard
can authorize startup of an unresolved datastore. Retry the appropriate stage
only after that review.
