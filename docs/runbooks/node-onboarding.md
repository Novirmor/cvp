# Add One Node to an Existing Cluster

Use this runbook **after** [first-host bootstrap](ansible-host-bootstrap.md)
has succeeded. `task onboard` does not provision a machine or initialize a
control plane; it rejects a target with `k3s_server_init: true`.

The concrete example adds a compute-only VM named `worker1` to the existing
`server1` cluster. Run from the repository root with the same controller,
operator key, and external operator configuration used for bootstrap. Replace
all documentation public addresses, key placeholders, and absolute paths.
`10.77.0.2` is an example in the previously selected RFC1918 mesh `/24`.

## 1. Confirm the existing fleet is ready

Before adding the new host to inventory:

```sh
export CVP_OPERATOR_CONFIG_FILE="$HOME/.config/cvp/operator.yml"
task verify
```

Expected: existing hosts and API pass verification. Keep both
`k3s_cluster_init_host` and `k3s_server_host` pointing to existing servers
(`server1` for this example). Every existing inventory node must be Ready,
non-terminating, and match its role and WireGuard InternalIP. Unexpected cluster
nodes, missing existing nodes, and unconfirmed additional servers block the join.

**Add one node at a time.** Do not stage several absent servers/workers in the
inventory and then try to onboard only one. The preflight permits only the
named target to be absent and checks the complete existing membership.

Review placement and recovery impact first. Keep exactly one ingress node;
adding another compute/server node does not make ingress or local data HA.
Before adding production data, complete the
[backup and restore gates](ansible-host-bootstrap.md#9-accept-the-host-and-establish-recovery-before-production).

## 2. Prepare the new host and its inventory

Use the [controller/host prerequisites](ansible-host-bootstrap.md#1-check-the-host-and-controller-prerequisites)
and [key and host-trust procedure](ansible-host-bootstrap.md#2-prepare-keys-and-trust-the-bootstrap-ssh-host)
for this host too. Recommended baseline: Debian 13/systemd/amd64 VM. Pin the
actual environment to `vm`, `metal`, or `lxc`; do not leave `auto`. LXC requires
provider-owned kernel, cgroup, TUN, and bridge facilities and must pass the
read-only probe. If no initial key-authenticated root SSH exists, stop at the
provider console to establish it.

Generate a **new** WireGuard pair outside the checkout, once:

```sh
umask 077
wg genkey > "$HOME/.config/cvp/worker1.wg-private"
wg pubkey < "$HOME/.config/cvp/worker1.wg-private" > "$HOME/.config/cvp/worker1.wg-public"
```

Create `ansible/inventory/host_vars/worker1.yml`; the repository's
`example-newnode.yml.example` documents additional fields:

```yaml
---
ansible_host: "203.0.113.21"      # bootstrap SSH; later change to its Tailscale IP
ansible_port: 22
ansible_private_key_file: "/home/operator/.ssh/cvp-ops"  # your existing absolute path
node_name: worker1
node_virtualization: vm
wireguard_address: "10.77.0.2"    # unique bare IPv4 in the existing /24
wireguard_endpoint: "203.0.113.21:51820"
wireguard_public_key: "REPLACE_WITH_WORKER1_WG_PUBLIC_KEY"
tailscale_address: ""
tailscale_advertise_tags: [tag:k3s]
k3s_role: agent
k3s_server_init: false
k3s_tls_sans: []
k3s_node_labels:
  - cvp.io/compute=true
k3s_node_taints: []
storage_enabled: false
storage_device: ""
storage_manage_device: false
storage_allow_format: false
```

In `ansible/inventory/hosts.yml`, retain `all.vars` from first-host bootstrap
(especially **both** server selections), and update `all.children` to:

```yaml
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

Adapt that mapping to retain **all** other existing hosts if the fleet is
already larger. Every mesh host must be in exactly one of `k3s_servers` and
`k3s_agents`, with a matching explicit role and boolean init flag. All inherit
the same init/API server, datastore, and local-path storage setting. Group vars
override inventory `all.vars`; validate the effective topology, not just the
text of `hosts.yml`.

The SSH endpoint and public WireGuard endpoint serve different purposes. Keep
the latter stable and reachable on UDP `51820` from existing peers; IPv6
endpoints use `"[public-ipv6]:51820"`. Provider firewall bootstrap SSH must use
the real controller egress `/32` or `/128`. This worker does not need public
`80`/`443` or ingress labels/tags. Preserve the three ingress labels on
`server1`; use [ingress relocation](ingress-relocation.md) for an intentional
move instead of assigning ingress to a second node.

`storage_enabled: false` skips host storage preparation; it **does not disable
K3s's local-path provisioner** or prevent a workload from requesting local
storage on this node. Use workload placement labels/affinity to express storage
intent. For a storage node, explicitly enable storage and follow the
[storage gate](../../ansible/README.md#controlled-bootstrap); the mountpoint
must equal the shared `/var/lib/rancher/k3s/storage` default. No formatting is
approved by this example. For custom label domains and ownership rules, see
[the host layer guide](../../ansible/README.md#inventory-inputs).

## 3. Add host-scoped credentials and prepare SSH access

Merge this entry into the **existing** external operator file; preserve the
`server1` settings and any backup settings:

```yaml
cvp_operator_hosts:
  # Keep existing host entries here too.
  worker1:
    wireguard_private_key: {env: WORKER1_WG_PRIVATE_KEY}
    tailscale_auth_key: {env: WORKER1_TAILSCALE_AUTH_KEY}
    firewall_ssh_ipv4_source_cidrs: ["203.0.113.10/32"]
    firewall_ssh_ipv6_source_cidrs: []
```

Replace the source CIDR with the actual controller egress address. Make the
file mode `0600`, and load the new auth key from your external secret manager;
it must authorize `tag:k3s` in the existing tailnet:

```sh
chmod 0600 "$CVP_OPERATOR_CONFIG_FILE"
export WORKER1_WG_PRIVATE_KEY="$(cat "$HOME/.config/cvp/worker1.wg-private")"
task validate-inventory
```

Onboarding converges existing hosts too. Every selected host using ordinary
unbound sshd needs an explicit SSH source CIDR matching the client source it
actually sees. For existing Tailscale connections, keep the controller's
Tailscale `/32` or `/128` in that host's operator entry, not its public egress
CIDR. Do not clear these lists just because the backend is `Running` or a private
login succeeds. CIDR-less approval requires the exact established socket to be
kernel-bound to `tailscale0` or the inventory WireGuard interface, with a direct
matching return route. If `SSH_CONNECTION` is unavailable, an independently
verified source CIDR is still required. See the
[private SSH migration procedure](ansible-host-bootstrap.md#7-move-ssh-to-the-private-address-before-closing-public-ssh).

**All environment references in the file must resolve on every invocation**,
including existing hosts' references. Keep them available, use literal strings
in the private file, or remove verified no-longer-needed enrollment/persisted-key
references as described in
[first-host operator settings](ansible-host-bootstrap.md#4-create-persistent-host-scoped-operator-settings).
Node enrollment keys are not provider API credentials. Do not put secrets in
inventory or use fleet-wide extra vars for private keys/format approvals.

Verify the new host's provider fingerprint, populate its trusted `known_hosts`
entry, and test root SSH **before** running:

```sh
CVP_ACCESS_NODE=worker1 CVP_ACCESS_CONFIRM=worker1 \
CVP_ACCESS_PUBLIC_KEY_FILE="$HOME/.ssh/cvp-ops.pub" \
CVP_ACCESS_ROOT_IDENTITY_FILE="$HOME/.ssh/provider-root" \
CVP_ACCESS_OPERATOR_IDENTITY_FILE="$HOME/.ssh/cvp-ops" \
  task prepare-access
task probe -- --limit worker1
```

Expected: `ops` login/passwordless sudo and the compatibility probe pass.
`prepare-access` touches only prerequisites/account/access; it does not change
networking or K3s. Its explicit identities are invocation-scoped and use strict
host-key checking without SSH-config/agent fallback. The persistent inventory
private-key path is what later site/onboarding connections use.

## 4. Run guarded onboarding

For this worker, leave `CVP_ONBOARD_SERVER_CONFIRM` unset:

```sh
unset CVP_ONBOARD_SERVER_CONFIRM
CVP_ONBOARD_NODE=worker1 CVP_ONBOARD_CONFIRM=worker1 task onboard
```

The wrapper runs these stages in order:

| Stage | Expected result |
| --- | --- |
| Local `task test` | Repository checks pass; credential-free checks may download dependencies/assets |
| Full-membership preflight | Initialized API `/readyz`; all existing nodes Ready and matching inventory; only the joining target may be absent |
| Target host probe | Read-only compatibility pass |
| Full-fleet site convergence | Recheck membership under lifecycle locks; distribute the new WireGuard peer to every host; join K3s and reconcile labels/taints |
| Target mesh/MTU probe | Peer connectivity and configured no-fragment payload pass |
| Full-fleet verification | All inventory nodes Ready with their WireGuard InternalIPs and live host/network/storage state verified |

Expected final message: `Onboarding verified for worker1.` The new node starts
with reserved bootstrap quarantine, removed atomically with desired placement
policy. Do not manually remove it to bypass a failed reconciliation.

The operation converges **the entire fleet**, not just `worker1`, because
existing peers need its public key and route. It pins the operator file digest
(or its absence) for every stage. Do not edit/create/remove that file during
the run. A failed stage stops the workflow without automatic rollback; follow
the failure procedure below rather than skipping gates.

### When the new node is another server

Use an existing **etcd** cluster and review quorum/recovery first. A two-server
etcd cluster needs both servers for quorum and tolerates no server failure;
three servers tolerate one failure. Prefer a planned three-server topology
when seeking control-plane fault tolerance, joining one server at a time.
SQLite permits only one server and cannot use this server-join path.

For a node named `server2`, use its own identity/address/keys, register it in
`wireguard` and `k3s_servers` (not `k3s_agents`), set `k3s_role: server`, and
keep `k3s_server_init: false`. Leave both shared server selections on existing
servers and leave the sole ingress selection unchanged. Then:

```sh
CVP_ONBOARD_NODE=server2 CVP_ONBOARD_CONFIRM=server2 \
CVP_ONBOARD_SERVER_CONFIRM=server2 task onboard
```

The extra confirmation must exactly match the joining server. Do not add a
second init server, reset the datastore, or point `k3s_server_host` at the
not-yet-joined target. A server's private API endpoint also needs the matching
TLS SAN before exporting a kubeconfig for that endpoint.

## 5. Finish private access and acceptance

Follow [the private SSH migration procedure](ansible-host-bootstrap.md#7-move-ssh-to-the-private-address-before-closing-public-ssh)
for `worker1`: read its assigned Tailscale IP, compare the private-address host
key to its trusted provider fingerprint, test a fresh private login and sudo,
and **change `ansible_host` and `tailscale_address` before removing public access**.
Verify Ansible connectivity through the new address, then replace `worker1`'s
public egress CIDR with the actual client's Tailscale `/32` or `/128` in its
existing operator entry. Keep that matching private source allowance for stock
unbound sshd; do not clear both lists. Then run:

```sh
task site
task probe-wireguard
task verify
mise exec -- kubectl --context cvp get nodes -o wide
```

Use the external `KUBECONFIG` exported during first-host bootstrap. Expected:
all nodes Ready, InternalIPs equal inventory mesh addresses, private SSH still
works after the public source exception is removed. Remove the provider public-SSH exception
too. Keep UDP `51820` open as required by the mesh.

Record live handshakes/path MTU and perform large cross-node TCP/UDP transfers,
placement and reboot checks. A limited `task verify -- --limit worker1` delegates
API reads to `k3s_server_host` but checks only selected nodes; it is not full
fleet acceptance. Label removal affects new scheduling and does not evict
existing pods; relocate workloads explicitly before relying on changed placement.

## If onboarding fails

- **Before mutating site:** fix tests, inventory, full membership, secrets,
  SSH/sudo, or compatibility. Inspect any partial `prepare-access` changes.
  These read-only gates do not acquire lifecycle locks.
- **During site:** later phases stop and acquired
  `/var/lib/cvp/lifecycle.lock` directories can remain across the fleet. Inspect
  every selected host's owner, running controller/host processes, and journals.
  Resolve the interrupted state before explicit lock cleanup; locks are never
  expired or stolen automatically. Do not blindly rerun or remove locks.
- **After successful site, during mesh/verification:** the join may already be
  complete and locks normally released. Diagnose live state before retrying.
  The named target may already exist; the preflight still requires the rest of
  the fleet to be healthy. Do not delete its Node or reset etcd to hide an error.
- **If recovery guard/staging exists:** follow
  [datastore recovery](../../ansible/README.md#datastore-restore) before any
  cleanup/startup. Never delete a restore guard just to unblock onboarding.

## Removing a node

Removal requires a separate reviewed operation: relocate ingress if applicable,
preserve affected local data, review quorum and backups, then drain workloads
and delete the Node using the explicit cluster context. K3s removes a deleted
server's embedded-etcd member; verify remaining quorum before host cleanup.
Stop/clean up the host's repository-managed K3s installation, remove its
inventory/host-vars and external operator entry together, then reconverge the
remaining fleet to remove the WireGuard peer. Do not assume an installer-created
uninstall script exists: this repository installs K3s directly. Replacing the
init/designated API server requires a coordinated topology/recovery change,
not merely deleting its inventory entry.
