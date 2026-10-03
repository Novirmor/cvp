# Ansible Host Layer

This directory owns operator-configured Debian/systemd hosts, the WireGuard
underlay, the host firewall, local-path storage preparation, the pinned
multi-master K3s installation, and the IPv6-to-IPv4 ingress frontend on the
ingress node.

Requirements: `kubernetes.core` (pinned in `requirements.yml`) is installed
project-locally by `task deps` (run from the repository root); `ansible.cfg`
points `collections_path` at it. Node labels and taints are reconciled through
the Kubernetes API with the `kubernetes.core` modules, never with shell
`kubectl` invocations. Hosts need `python3-kubernetes` (>= 24.2, e.g. Debian
trixie or newer) and `python3-jsonpatch` — both in `base_packages`; verify the
distro version during the host bootstrap gate.

## Inventory inputs

The default `inventory/hosts.yml` contains no hosts and provisions none.
`k3s_cluster_init_host` and `k3s_server_host` are empty by default; the operator
must select the initial server explicitly before convergence.

Create operator-supplied files under `inventory/host_vars/` with node names,
WireGuard addresses and public keys, stable public endpoints, SSH endpoints,
K3s roles, and placement labels. Documentation examples use `server1` and the
synthetic mesh `192.0.2.0/24`; replace these before use. Leave
`tailscale_address` empty until Tailscale assigns it at enrollment. Each host
carries a `node_virtualization` classification (`lxc`, `vm`, `metal`, or `auto`) that the
probe, the base role, and verification all validate against
`systemd-detect-virt` with the same shared identifier lists. LXC guests share
the host kernel, so the probe requires usable host-provided modules, cgroup
delegation, TUN, and bridge sysctls. Convergence
never loads modules or disables host-owned swap there; VM and metal hosts get
their kernel modules loaded and persisted by the base role. Forwarding-enabled
uplinks retain IPv6 router advertisements via `accept_ra=2`. Before a fresh
host probe, the OS must have `kmod` and `procps` available; `task probe` is
read-only and does not install packages or require an active WireGuard mesh.
Initial bootstrap follows `docs/runbooks/ansible-host-bootstrap.md`.
Subsequent nodes onboard through `docs/runbooks/node-onboarding.md` and the
`inventory/host_vars/example-newnode.yml.example` template.

Node labels are declared per host in `k3s_node_labels`; `cvp.io/role` is
derived automatically from `k3s_role`. Validation rejects reserved
`kubernetes.io/` and `k8s.io/` keys, unknown or non-boolean `cvp.io/` catalog
tags, and any label whose key does not match an anchored regex in
`k3s_managed_label_domains` (`inventory/group_vars/all.yml`): a declared label
is always both applied and reconciled away on removal, so a label outside the
managed domains is rejected with an explanation instead of drifting.
Custom domains are brought under reconciliation by adding their anchored,
escaped literal DNS prefix to `k3s_managed_label_domains` in one reviewed
change; arbitrary regexes are rejected. Labels already on
a node outside the managed domains are never modified or removed.
`site.yml` checks inventory before configuring hosts; mismatched `node_name`
or invalid tags stop that run. `task test` exercises the same validation,
negative cases, and offline Node patch regressions.

Each host's public WireGuard key is persisted in its inventory file and is the
authentication source for every peer. Prepare keys out of band before the
first convergence: generate one key pair per host in the secret store (or run
`wg genkey`/`wg pubkey` locally), distribute each private key to its host
through the secret store or `wireguard_private_key`, and record each public
key in the matching `inventory/host_vars/` file. The role fails when a host's
selected private key does not derive the inventory public key, and when any
peer's inventory key is missing, so a placeholder or a regenerated key can
never silently partition the mesh. Rotation is a coordinated procedure:
update every peer's inventory key in one reviewed change while supplying the
new private key to its host. Private keys never enter Git.

## Controlled bootstrap

All operations run through the repository Taskfile from the repository root
(`task --list` shows the full surface):

```sh
task site -- --syntax-check
task site -- --check --diff
task site
task verify
task probe
task probe-wireguard
CVP_ACCESS_NODE=server1 CVP_ACCESS_CONFIRM=server1 \
  CVP_ACCESS_PUBLIC_KEY_FILE=/secure/operator.pub task prepare-access
```

For initial bootstrap, register the selected server (example `server1`) in
`wireguard` and `k3s_servers`, set its `k3s_role: server` and
`k3s_server_init: true`, and configure both `k3s_cluster_init_host` and
`k3s_server_host` to its inventory name in `inventory/group_vars/all.yml` and
`inventory/hosts.yml`'s `all.vars`, respectively. Supply its WireGuard key and prepare
administrative access, then follow the host bootstrap runbook with `task probe`,
`task site`, `task probe-wireguard`, and `task verify`.

`task onboard` adds subsequent nodes to an initialized cluster; it rejects a
cluster-init target and cannot bootstrap the first server. Once a joining
host's inventory, WireGuard key, and administration path are prepared, run:

```sh
CVP_ONBOARD_NODE=<node> CVP_ONBOARD_CONFIRM=<node> task onboard
```

It validates the target, runs `task test` and the read-only host probe, then
converges the **entire**
fleet so every existing WireGuard peer learns the node. It follows with the
post-convergence peer/MTU probe and full verification. A new etcd server
requires the additional `CVP_ONBOARD_SERVER_CONFIRM=<node>` gate; for
temporary SSH CIDRs or external keys, supply an absolute
`CVP_ONBOARD_SITE_VARS_FILE` outside Git. Review host compatibility, storage
impact, and access before applying Ansible.

The normal play changes host state. Do not run it against a live node until the
host compatibility gate and recovery or accepted-loss review have passed. The
firewall defaults to private SSH through Tailscale or WireGuard. During initial
bootstrap, supply temporary trusted SSH CIDRs as a JSON list (a bare string is
rejected) and remove them after Tailscale is enrolled and verified:

```sh
task site -- -e '{"firewall_ssh_ipv4_source_cidrs":["203.0.113.10/32"]}'
```

The firewall refuses to activate unless a bootstrap CIDR is supplied or the
Tailscale backend reports state `Running`; an enrolled-but-logged-out daemon
is not accepted as an administration path.

For a new machine without the `ops` account, verify its SSH host fingerprint
and initial root SSH access first, then use `task prepare-access` with the
approved operator public key file as shown above. The helper uses
`bootstrap-access.yml` to install minimal Ansible prerequisites and grant
`ops` SSH plus passwordless sudo; it verifies both login and elevation. It
does not load K3s modules, edit sysctls, harden SSH, or apply a firewall.
The public key must correspond to a private key already available in the
operator's SSH agent/config or passed as the absolute
`CVP_ACCESS_OPERATOR_IDENTITY_FILE` outside Git. A separate provider root
identity can be supplied as `CVP_ACCESS_ROOT_IDENTITY_FILE`. For manual
break-glass invocation of the low-level playbook, restrict it to one host
and connect as root without invoking sudo:

```sh
CVP_BOOTSTRAP_ADMIN_KEYS='["ssh-ed25519 AAAA..."]' \
task bootstrap-access -- --limit server1 -e ansible_user=root -e ansible_become=false
```

The K3s release is pinned in `group_vars/all.yml`. Downloads are verified using
the matching release `sha256sum-*.txt` asset. Review and update that version as
part of the K3s acceptance gate rather than switching to a channel or install
script.

## Multi-master control plane

Inventory nodes may be servers or agents, as selected by the operator. The one
server with `k3s_server_init: true` initializes the embedded etcd datastore
(`cluster-init`) and generates the shared server token and agent token; the
secrets-encryption config is distributed to joining servers through the
datastore bootstrap automatically. The joining servers (`k3s_server_init:
false`) run in a separate play that waits for the init server, receive both
tokens over the WireGuard mesh, and start with `server:` + `token-file`
pointing at the init supervisor selected by `k3s_server_host`. Quorum tolerance
depends on server count; a three-server deployment tolerates one server failure.
The restore runbook covers etcd recovery. `k3s_datastore: sqlite` remains
available for a deliberate single-server setup.

Node labels and optional taints are declared per host as `k3s_node_labels`
(list of `key=value`) and `k3s_node_taints` (list of `key=value:effect`).
Feature tags are orthogonal booleans (`cvp.io/compute=true`,
`cvp.io/storage=true`, `cvp.io/gpu=true`, `cvp.io/ingress=true`,
`cvp.io/system=true`, `cvp.io/stateful=true`) that combine for allocation:
a workload selects the tags it needs and all terms must match, or it offers
multiple `nodeSelectorTerms` for alternatives. `site.yml` reconciles labels
and taints through the Kubernetes API on every convergence and removes
obsolete managed labels. Taints are reconciled only when recorded as owned
in the Node's `cvp.io/managed-taints` annotation; Kubernetes/controller taints
are preserved and matching unowned taints cause a conflict rather than silent
adoption. Removing a placement label does not evict running pods; planned
relocation requires a separate rollout. `task probe-wireguard` verifies peer
connectivity and path MTU after convergence. The Ansible
host firewall permits the etcd client and peer ports (2379/2380) between
servers over `wg0`.

## Backup enablement

The server role installs the backup script and systemd units on every run. The
timer is disabled until an age recipient and off-host upload command are
provided. The command receives `BACKUP_FILE` and `BACKUP_CHECKSUM_FILE` in its
environment; it must upload both files to the selected encrypted off-host
store.

```sh
K3S_BACKUP_AGE_RECIPIENT='age1...' \
task site -- \
  -e k3s_backup_enabled=true \
  -e 'k3s_backup_upload_command=install -m 0600 "$BACKUP_FILE" /mnt/off-host/' \
  -e 'k3s_backup_writable_paths=["/mnt/off-host"]'
```

The upload target must be listed in `k3s_backup_writable_paths`: the systemd
unit runs with `ProtectSystem=strict` and only the backup directory plus those
paths are writable. Each backup-enabled server runs its own timer, so snapshot
frequency scales with server count and a surviving backup-enabled server keeps
the backup path alive.

The script takes an etcd snapshot (`k3s etcd-snapshot save`) for the default
`etcd` datastore, or a SQLite `.backup` for `sqlite` mode, and archives the
matching server and agent tokens, the node marker, and the recorded runtime
K3s version in the same age-encrypted recovery unit. A restore drill remains
required; a successful timer run is not restore evidence.

## Verification scope

`playbooks/verify.yml` is read-only. It checks WireGuard state and address,
firewall syntax, Tailscale status, systemd services, local-path mounting, and
the K3s node list. The Flannel pod MTU must be published and equal `1370` (for
the configured `1420` WireGuard MTU plus VXLAN overhead) and every inventory
node must be present and `Ready`; missing values are failures, not skips.

`playbooks/restore-k3s.yml` is deliberately destructive and must run with
`--limit` on exactly one target server (enforced by an assertion). It validates
the recovery unit on the controller first (checksum, decryption, archive
members, version match against the installed binary, and SQLite integrity in
sqlite mode), then stops K3s, snapshots the current state for rollback,
installs the verified datastore and tokens, and starts K3s again. In `etcd`
mode the target is reset from the snapshot with
`k3s server --cluster-reset --cluster-reset-restore-path` using a temporary
config with the join URL removed (cluster-reset refuses to run with `server:`
configured); etcd snapshots are cluster-wide, so restoring a unit taken on
another member onto a survivor is supported. Before the restore: stop K3s on
the other servers. After a verified restore (or a rollback): delete
`/var/lib/rancher/k3s/server/db` on each peer before restarting it so the
peer rejoins instead of hitting a cluster-ID mismatch. On failure the play
stops K3s, rolls back, and preserves the rollback material under
`/var/lib/rancher/k3s/.restore/<run>/` for inspection. It requires:

```sh
K3S_RESTORE_CONFIRM=true \
K3S_RESTORE_CONFIRM_HOST=server1 \
K3S_RESTORE_ARCHIVE=/secure/path/k3s-backup.tar.gz.age \
K3S_RESTORE_CHECKSUM=/secure/path/k3s-backup.tar.gz.age.sha256 \
K3S_RESTORE_AGE_IDENTITY=/secure/path/agekey.txt \
task restore-k3s -- --limit server1
```

Optional: `K3S_RESTORE_EXPECT_NAMESPACES` (comma-separated; default
`kube-system`) lists namespaces the restored datastore must contain, and
`K3S_RESTORE_ALLOW_VERSION_MISMATCH=true` bypasses the binary-version match
after a reviewed skew decision. A restore drill on disposable
infrastructure remains mandatory; a passing timer is not restore evidence.
