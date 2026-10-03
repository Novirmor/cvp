# Node Onboarding Runbook

Nodes may be LXC guests or ordinary VMs (or metal). Both are supported, but
the compatibility probe holds LXC guests to stricter shared-kernel
requirements because an LXC guest cannot load kernel modules itself. Pin each
node's `node_virtualization` (`lxc`, `vm`, or `metal`) instead of leaving
`auto`: a pinned declaration that later disagrees with `systemd-detect-virt`
fails the probe, convergence, and verification, so a silently migrated or
rebuilt node surfaces as a hosting decision instead of wrong behavior.

## Initial bootstrap prerequisite

The default inventory contains no hosts and provisions none.
`k3s_cluster_init_host` and `k3s_server_host` are empty by default. The operator
must populate inventory, select the initial server (example `server1`), and
complete `ansible-host-bootstrap.md` first. Mesh examples use the synthetic
`192.0.2.0/24` range and must be replaced with operator-assigned addresses.

`task onboard` requires an initialized control plane and rejects a target with
`k3s_server_init: true`; it does not bootstrap the first server.

## Adding a subsequent node

1. Copy `ansible/inventory/host_vars/example-newnode.yml.example` to
   `ansible/inventory/host_vars/<node>.yml`. Fill in its SSH endpoint, unique
   WireGuard address and public key, exact `node_name`, **pinned**
   `node_virtualization` (`lxc`, `vm`, or `metal`), and desired labels/taints.
   Register it in `ansible/inventory/hosts.yml` under `wireguard` and exactly
   one of `k3s_agents` (the worker default) or `k3s_servers` (requires a
   reviewed etcd quorum decision). Add custom tag domains as below.
2. Prepare access: verify the new host's SSH fingerprint with the provider
   and establish a trusted `known_hosts` entry and initial **root** SSH
   connection. Put the approved operator SSH public key in a one-line file;
   the corresponding private key must be available in the operator's SSH
   agent/config (or set `CVP_ACCESS_OPERATOR_IDENTITY_FILE` to its absolute
   path outside Git). Then run:

   ```sh
   CVP_ACCESS_NODE=<node> CVP_ACCESS_CONFIRM=<node> \
   CVP_ACCESS_PUBLIC_KEY_FILE=/secure/operator.pub task prepare-access
   ```

   This installs only Python, sudo, and the host-probe tools if missing,
   creates `ops` with the approved public key and passwordless sudo, and
   verifies both its SSH login and sudo. If the provider root login needs
   a dedicated key, set `CVP_ACCESS_ROOT_IDENTITY_FILE` too. It never
   configures the firewall, WireGuard, or K3s. Initial root SSH access
   cannot be created by a script that cannot yet reach the host. Prepare
   the WireGuard private key on the host or supply it securely at runtime;
   if onboarding also needs a temporary SSH CIDR or Tailscale auth key, put
   the Ansible extra vars in a file **outside** this repository and set
   `CVP_ONBOARD_SITE_VARS_FILE` to its absolute path.
3. After reviewing host compatibility, access, storage, and quorum impact, run one guarded
   command from the repository root:

   ```sh
   CVP_ONBOARD_NODE=<node> CVP_ONBOARD_CONFIRM=<node> task onboard
   ```

   Adding a server also requires `CVP_ONBOARD_SERVER_CONFIRM=<node>` after
   reviewing quorum impact. The confirmation must exactly match the node;
   `task onboard` runs `task test`, probes the new host **read-only**, then
   converges the **full fleet** so existing WireGuard peers trust the new
   node. It checks the converged mesh/MTU and verifies all nodes. A failed
   stage stops the workflow; there is no automatic rollback. Fix the cause,
   review any partial host changes, and rerun rather than skipping a gate.

## What the compatibility gate checks

| Environment | Before convergence | Host role behavior |
| --- | --- | --- |
| `lxc` | Overlay, loaded or built-in modules, delegated cgroups, TUN access, and provider-owned bridge sysctls | Checks host facilities without loading modules or disabling shared swap; configures writable guest sysctls and preserves IPv6 router advertisements |
| `vm` | Required kernel modules available (`modprobe --dry-run`) | Loads `br_netfilter`, `overlay`, and `vxlan`, persisting them across reboots |
| `metal` | Like `vm`, without a hypervisor | Like `vm` |

If the public uplink cannot be identified from a default route, declare
`firewall_external_interface` in host_vars. A failed LXC probe is a hosting
decision: ask the provider to expose the facilities or choose a VM, not an
excuse to silently increase guest privileges. Node labels and taints are
validated offline before host mutation; `cvp.io/role` is derived, not declared.

## Custom tag domains

Custom tags follow a two-step contract so that every declared label is fully
reconciled — applied when declared, removed when deleted from inventory:

1. Add an anchored, escaped **literal DNS prefix** to
   `k3s_managed_label_domains` in `group_vars/all.yml` (for example
   `'^example\.com/'`). Arbitrary regexes, wildcards, and unescaped dots are
   rejected because they could delete unrelated Node labels.
2. Declare the labels per host in `k3s_node_labels` (for example
   `example.com/zone=fra`). Workloads select them with node selectors or
   affinity exactly like `cvp.io/` tags.

Labels already present on a node outside the managed domains — set manually
or by other controllers — are never touched. Declaring a label without adding
its domain first fails validation with an explanation, because such a label
would be applied but never reconciled away. Removing a tag affects **new**
scheduling, but it does not evict pods already running on that node; explicitly
relocate affected workloads before depending on the new placement. Taints
declared in `k3s_node_taints` are tracked in the Node's
`cvp.io/managed-taints` annotation; Kubernetes/controller taints are
preserved. An existing matching taint without that ownership record is a
conflict requiring an explicit review, not automatically adopted or erased.

## Removing a node

Removal is destructive. Review workload placement and quorum impact, and verify
backups or record accepted loss for affected local data before proceeding.

1. Drain the node's workloads and delete the Node object through kubectl; K3s
   then removes an embedded-etcd member automatically. Confirm the remaining
   quorum is healthy before touching the host.
2. Uninstall K3s on the host and remove the WireGuard peer from every other
   node's inventory in the same reviewed change.
3. Remove the host_vars file and the inventory entries together so the mesh
   and the cluster agree on the node set.
