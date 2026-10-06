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

Local tests use the pinned mise uv/Ansible environment with `jsonpatch` and
`jsonpointer`. After dependency changes, an existing installation may need
`mise install --force pipx:ansible-core`. Install the local `sqlite3` CLI and
OpenSSH tools: the rendering regression requires `ssh-keygen` and a real `sshd`
parser on `PATH` or at `CVP_TEST_SSHD`, without starting a daemon. See the root
README for the separate firewall and WireGuard kernel integration tasks and
their unprivileged namespace/tool requirements.

## Inventory inputs

An instance's `inventory/hosts.yml` starts with no hosts and provisions none
(the platform tests use the empty `examples/instance`).
`k3s_cluster_init_host` and `k3s_server_host` are empty by default; the operator
must select the initial server explicitly before convergence.

Site validates the **whole** topology before host access, including under
`--limit`. Required invariants:

- `k3s_servers` and `k3s_agents` exclusively partition `wireguard`; every node
  has a matching explicit `k3s_role`, `node_name`, and boolean `k3s_server_init`.
- Exactly one server has `k3s_server_init: true`, named by
  `k3s_cluster_init_host`; `k3s_server_host` names a server. All nodes agree on
  these settings and `k3s_datastore`; SQLite permits only one server.
- Exactly one mesh node belongs to `ingress`. Mesh addresses are unique usable
  IPv4 addresses in one `/24`, public keys are unique, and
  `wireguard_peers_group` selects the full `wireguard` group.
- `k3s_default_local_storage_path` is one shared canonical absolute directory.
  Every storage-enabled node's `storage_mountpoint` **must equal** that path;
  heterogeneous per-node paths are unsupported.

Persistent operator settings live outside Git in
`$XDG_CONFIG_HOME/cvp/<instance>/operator.yml`, or `~/.config/cvp/<instance>/operator.yml` when
`XDG_CONFIG_HOME` is unset. Set `CVP_OPERATOR_CONFIG_FILE` to select another
absolute external path. An absent default file means no overrides; an explicit
missing file fails. Keep files containing credentials private.

`site.yml`, `probe.yml`, `probe-wireguard.yml`, and `verify.yml` import
`load-operator-config.yml` before host access, including in check mode. The
controller validates the structure with `scripts/cvp_wrapper_common.py`, then
merges `cvp_operator_defaults` with only the selected host's entry:

```yaml
cvp_operator_defaults:
  tailscale_accept_dns: false
cvp_operator_hosts:
  server1:
    firewall_ssh_ipv4_source_cidrs: ["203.0.113.10/32"]
```

Replace the example hostname and bootstrap source before use. This is a
structured configuration file, not a global `-e @file` input. Unknown inventory
hosts, duplicate keys, identity/connection overrides, and per-node inputs in
defaults are rejected. Keep SSH connection settings, node roles, mesh addresses,
public keys, and init/join topology in inventory. Private WireGuard keys,
Tailscale enrollment keys, storage-device approvals, and destructive
confirmations belong in the appropriate `cvp_operator_hosts` entry.

Values are literal data, not Jinja expressions. Only `wireguard_private_key`
and `tailscale_auth_key` accept references: a private file such as
`wireguard_private_key: {file: /home/operator/.config/cvp/example/keys/server1.wg-private}`
(absolute, outside the checkout, a regular file owned by you with mode `0600`,
one line), or an environment variable such as
`wireguard_private_key: {env: SERVER1_WG_PRIVATE_KEY}`. Referenced values must
be present, nonempty, and free of control characters; literal credential
strings are also supported. Other fields cannot use references.

Create operator-supplied files under the instance's `inventory/host_vars/` with node names,
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
Every node, including the initial server, starts as a fresh Debian install and
is scaffolded, bootstrapped, and joined through `docs/runbooks/nodes.md`
(`task node-new`, `task node-bootstrap`, `task node-join`). `examples/instance/inventory/host_vars/example-newnode.yml.example`
documents each host variable for hand edits.

Node labels are declared per host in `k3s_node_labels`; `cvp.io/role` is
derived from `k3s_role`. Validation rejects reserved Kubernetes keys, invalid
catalog tags, mismatched `node_name`, and labels outside
`k3s_managed_label_domains` before host configuration. Custom domains require
anchored, escaped literal DNS prefixes; arbitrary regexes are rejected. Declared
labels are reconciled away on removal, while labels outside managed domains are
preserved. `task test` covers validation and offline Node patch regressions;
the tag catalog is in `ARCHITECTURE.md`.

Each host's public WireGuard key is persisted in its inventory file and is the
authentication source for every peer. Prepare keys out of band before the
first convergence: `task node-new` generates one key pair per host into
`~/.config/cvp/<instance>/keys/` and references it from the operator file (or generate one
in the secret store), distribute each private key to its host
through the secret store or `wireguard_private_key`, and record each public
key in the matching `inventory/host_vars/` file. The role fails when a host's
selected private key does not derive the inventory public key, and when any
peer's inventory key is missing. Existing persisted or active-interface keys
take precedence over an ordinary supplied key. For rotation, update the
rotating host's public key in inventory and set its host-scoped
`wireguard_private_key`, `wireguard_rotate_private_key: true`, and
`wireguard_rotation_confirm` equal to its inventory hostname. The role validates
the new pair before replacing the persisted key. Converge the fleet in a
coordinated maintenance window so every peer learns the new public key; rotation
is not atomic across nodes. Remove the rotation opt-in and confirmation after
verification. Private keys never enter Git.

Peer, key, port, keepalive, and MTU updates reconcile in place with `wg syncconf`
and live checks; they do not restart `wg-quick` or trigger K3s dependency restarts.
A missing interface may be started, but inconsistent interface/service ownership
fails. The helper supports the rendered single IPv4 `/24` mesh with peer `/32`
routes inside it; interface renames, configured address migrations, and other
configuration shapes require explicit coordinated maintenance. Unchanged endpoint
intent preserves authenticated roaming; changed intent is applied. Verification
allows learned/resolved endpoint values rather than comparing them literally
with configured DNS names or addresses.

An active interface must also have its kernel-connected mesh `/24` route with
the configured source address, and every peer route must resolve directly through
the managed interface. Missing routes, competing peer routes, and policy-routing
diversions fail before convergence mutates an otherwise active interface; correct
them through explicit routing maintenance. Even a single-node mesh with no peers
requires its connected route. An absent or down interface is not reported as
verified: inspection permits the normal startup/in-place recovery path, then
convergence checks routing after activation before recording success.

When `base_manage_admin_user` is enabled, `base_admin_authorized_keys` owns the
configured account's **complete** authorized-key set: omitted keys are revoked.
Supply all intended keys together; empty sets and malformed keys fail before
replacement. RSA, Ed25519, and ECDSA keys are validated with `ssh-keygen`.
`base_manage_sshd` installs the hardening policy before existing global settings
and checks effective `sshd -T` output before reload. Add connection-specific
`base_sshd_validation_contexts` for additional `Match` cases needing coverage.

SSH, journald, and IPv6 ingress activation records combine input fingerprints
with systemd invocation IDs after successful activation. Ingress also verifies
listener ownership by the expected PID. Failed activation removes success
evidence so an unchanged pending configuration is retried on the next run.

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
`k3s_server_host` to its inventory name in `inventory/hosts.yml`'s `all.vars`.
Supply its WireGuard key and prepare
administrative access, then follow the host bootstrap runbook with `task probe`,
`task site`, `task probe-wireguard`, and `task verify`.

Site acquires `/var/lib/cvp/lifecycle.lock` on **all selected hosts** before
host convergence, then verifies ownership at mutation boundaries. Mutating
`--limit` selections must include both `k3s_cluster_init_host` and
`k3s_server_host` to lock every shared control-plane/credential dependency.
All phases use `any_errors_fatal`; a failure
stops later phases and retains acquired locks. Locks are released only after
successful label/taint reconciliation. Check mode checks lock availability
without acquiring ownership or activating services.

There is no automatic lock expiry or stealing. After a failed run, inspect the
lock's `owner`, controller/host processes, journals, and any restore guard and
staging. Explicit cleanup is allowed **only after verifying no owning operation
is still running** and resolving the interrupted state. Inspect every selected
host: even a partial lock-acquisition failure can leave locks behind. Do not
remove a lock merely to make a retry proceed.

`task node-join` joins one node (see `docs/runbooks/nodes.md`). For the sole
cluster-init node it bootstraps the first server; for every later node it
refuses a cluster-init target. Once `task node-new` has written the node, run:

```sh
task node-join -- <node> --confirm <node>
```

It validates the inventory, ensures operator access, and probes the target, then
checks the initialized API's `/readyz` and **all** cluster membership.
Every existing inventory node must be present, non-terminating, Ready, and match
its role and mesh InternalIP; unexpected nodes or unconfirmed additional servers
fail preflight. Only the named joining target may be absent. A new etcd server
requires `--server-confirm <node>`; an agent must not carry that gate.
The helper converges the **entire fleet** so every peer learns the node, repeating
the membership preflight under lifecycle locks before host changes. It follows
with the target's peer/MTU probe and full verification.

The command pins the persistent operator file's digest and every referenced
credential file, or pins the file's absence, for every stage. Editing/removing
a pinned file or introducing one into an absent-config run stops the join.
Progress is recorded so a rerun resumes after the last completed mutating stage;
an interrupted `site` requires `--retry-reviewed` after inspection. `task
onboard` (`CVP_ONBOARD_NODE`, `CVP_ONBOARD_CONFIRM`) remains as an alias; its
`CVP_ONBOARD_SITE_VARS_FILE` is a deprecated alias for `CVP_OPERATOR_CONFIG_FILE`. Review storage impact and access before applying Ansible.

The normal play changes host state. Do not run it against a live node until the
host compatibility gate and recovery or accepted-loss review have passed. The
firewall accepts SSH only on the public uplinks, from the trusted SSH CIDRs in
the target's operator entry. Put them there as a list, then use that same
configuration for convergence and verification:

```sh
CVP_OPERATOR_CONFIG_FILE=/secure/cvp/operator.yml task site
CVP_OPERATOR_CONFIG_FILE=/secure/cvp/operator.yml task verify
```

The firewall installs `iproute2` before administration preflight. For an
available SSH session, a source CIDR must match the **public client address the
host actually sees**, and the session must not target a Tailscale or WireGuard
address: neither interface accepts SSH. SSH source CIDRs that overlap the
Tailscale ranges or the mesh `/24` (including `0.0.0.0/0` and `::/0`) are
rejected. Without `SSH_CONNECTION`, an explicit CIDR is still required. The
helper's rejection prints the matching CIDR to add to that host's external
operator settings.

Public `80`/`443` on the ingress node accept only
`firewall_public_ingress_ipv4_source_cidrs` and
`firewall_public_ingress_ipv6_source_cidrs`, which default to Cloudflare's
published ranges (refresh them from <https://www.cloudflare.com/ips/> when
Cloudflare announces a change). The same restriction applies to DNAT traffic
forwarded to ServiceLB. An empty list closes public ingress for that family.

K3s servers add their live Tailscale addresses to the API certificate SANs on
every convergence, so people can reach the API over the tailnet without
editing `k3s_tls_sans`.

If `SSH_CONNECTION` is unavailable even after the unprivileged fallback, an
explicit independently verified source CIDR is required. Preflight reports
`connection-proof-unavailable`: it checks the listener, but cannot verify that
the allowlist matches the absent session. An enrolled Tailscale backend does not
replace this requirement. Check mode performs these read-only guards too; on a
fresh host, install the inspection tools before relying on a check-mode preview.
Enrollment uses a private temporary credential file with cleanup, and an empty
`tailscale_advertise_tags` explicitly clears the client advertisement.

For split public uplinks, set `firewall_external_ipv4_interface` and
`firewall_external_ipv6_interface`; defaults use the legacy/IPv4 selection and
the IPv6 default route respectively. Public forwarding permits only DNAT flows
whose original destination is an ingress uplink address on an approved TCP port.
Established and private-interface paths remain available. The input policy also
permits approved ingress ports on Tailscale, ICMPv6 through extension headers,
and link-local DHCPv6 replies. nftables reload and stop operations are scoped to
the owned `cvp_filter` table.

Activation records both the applied file hash and normalized live owned-table
state. Verification checks that evidence against the live table and current
file, detecting missing/tampered rules and unapplied configuration rather than
accepting syntax alone.

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

The K3s release is pinned in `ansible/defaults/group_vars/all.yml`. Downloads are verified using
the matching release `sha256sum-*.txt` asset. Review and update that version as
part of the K3s acceptance gate rather than switching to a channel or install
script.

The storage role inspects its target before changing it, including in check mode.
`storage_mountpoint` must equal the fleet's shared
`k3s_default_local_storage_path` on every storage-enabled node (default
`/var/lib/rancher/k3s/storage`), including directory-backed storage.
A device-backed mount must match its resolved device, unique UUID, filesystem,
and exact mountpoint. Existing ext4/XFS filesystems can be mounted after these
checks. Automatic formatting is limited to ext4 on an unmounted, conclusively
blank device: copy preflight's exact `<host>:<resolved-device>:<sha256>` token to
`storage_format_confirmation`, and set `storage_manage_device: true` and
`storage_allow_format: true` in the host's operator entry. The entire
candidate must pass a readable all-zero scan; missing filesystem signatures
alone are insufficient. Probes have a 15-second budget, the whole-device zero
scan has a 300-second budget, and each inspection has a 600-second outer budget
with a five-second kill grace period. These bounds also apply in check mode;
timeouts fail closed and do not authorize formatting or mounting. Prepare large
or slow devices outside the role rather than bypassing the safety gate. Existing directory-backed
storage converges its configured ownership and mode (default `0750`); check mode
previews those permission changes without applying them.
Clear format approvals after provisioning. The role does not mount over a
populated directory or migrate data. Mappings, conflicting or nested mounts,
holders, active swap, and ambiguous identities require manual
preparation/review rather than bypassing the gate.

## Multi-master control plane

Inventory nodes may be servers or agents, as selected by the operator. The one
server with `k3s_server_init: true` initializes the embedded etcd datastore
(`cluster-init`). K3s generates the shared server token, and Ansible provisions
the dedicated agent token. Secrets-encryption config reaches joining servers
through datastore bootstrap automatically. The joining servers (`k3s_server_init:
false`) run in a separate play that waits for the init server, receive both
tokens through Ansible's configured SSH connections, and start with `server:` +
`token-file` pointing at `k3s_cluster_init_host` over WireGuard. Agents use
`k3s_server_host`. Quorum tolerance depends on server count; a three-server
deployment tolerates one server failure.
The restore runbook covers etcd recovery. `k3s_datastore: sqlite` remains
available for a deliberate single-server setup.

Servers and agents fingerprint their activation inputs, including relevant
tokens, and verify the running binary version before recording successful
activation. Check mode previews configuration; it does not perform token
exchange or prove activation. kube-proxy uses iptables mode with NodePort
addresses restricted to `127.0.0.1/32`, the node's exact WireGuard `/32`, and
`::1/128`; the explicit IPv6 entry prevents an absent-family wildcard. Keep
Traefik's LoadBalancer NodePorts allocated: ServiceLB with
`externalTrafficPolicy: Local` requires them. The separate original-destination
firewall policy controls public exposure; do not disable allocation as a substitute.

`k3s_node_labels` contains `key=value` entries and `k3s_node_taints` contains
`key=value:effect` entries. `site.yml` reconciles both through the Kubernetes API;
only taints recorded in `cvp.io/managed-taints` may be removed. Matching unowned
taints cause a conflict, and controller taints are preserved. The bootstrap
exception is the reserved registration pair
`cvp.io/bootstrap=true:NoSchedule` and `cvp.io/bootstrap-quarantine=true`, which
inventory cannot declare. New servers and agents register quarantined; a single
concurrency-checked JSON patch per node applies desired labels/taints and their
ownership ledger while removing that pair. Quarantine is not released separately
before desired scheduling policy is installed, and lifecycle locks remain held
until reconciliation succeeds. Removing a placement label does not evict
running pods; relocate them through a separate rollout. `task probe-wireguard`
tests peer connectivity with the configured
no-fragment ping payload; large cross-node TCP/UDP transfers remain a separate
acceptance test. The host firewall permits etcd ports 2379/2380 over `wg0`.

## Backup enablement

Keep backup enablement, recipient, schedule, upload command, and writable paths
in the persistent operator configuration. One-off enablement through `-e` is
not a durable configuration: a later run without it would request disablement.
The server role checks timer enablement and timer/service activity before K3s
changes. Disabling enabled or busy backups requires the host-scoped
`k3s_backup_disable_confirm` equal to that inventory hostname. Unknown or
inconsistent unit state fails closed; restore the persistent settings or resolve
the state before proceeding.

`/var/lib/cvp/k3s-backup-identity.json` records the applied timer, service, and
script identity. Convergence and restore also inspect prior backup units.
Changing names or script paths fails closed even when backups are now disabled:
restore the prior settings or explicitly migrate retired units and the ledger.
A rename cannot silently abandon an old schedule or bypass disablement checks.

For an already prepared and verified off-host mount at `/mnt/off-host`, merge
these settings into the selected server's operator entry, replacing the recipient:

```yaml
cvp_operator_hosts:
  server1:
    k3s_backup_enabled: true
    k3s_backup_age_recipient: "<age-recipient>"
    k3s_backup_writable_paths: [/mnt/off-host]
    k3s_backup_upload_command: >-
      destination="/mnt/off-host/$(basename "$BACKUP_BUNDLE_DIR")";
      mkdir -m 0700 -- "$destination";
      install -m 0600 -- "$BACKUP_FILE" "$BACKUP_CHECKSUM_FILE" "$destination/"
```

Run `task site` with that persistent configuration. Each invocation publishes a
unique bundle directory, exported as `BACKUP_BUNDLE_DIR`, containing
`BACKUP_FILE` and `BACKUP_CHECKSUM_FILE`. The upload command must copy **both**
files successfully; preserve their names so checksum verification works.
The upload target must be listed in `k3s_backup_writable_paths`: the systemd
unit runs with `ProtectSystem=strict` and only the backup directory plus those
paths are writable. Each backup-enabled server runs its own timer, so snapshot
frequency scales with server count and a surviving backup-enabled server keeps
the backup path alive.

The bounded, single-writer script takes an etcd snapshot
(`k3s etcd-snapshot save`) or a SQLite `.backup` for `sqlite` mode, and archives the
matching server and agent tokens, the node marker, and the version of the
running K3s process in the same age-encrypted recovery unit. It rejects a
concurrent recovery or changed process/tokens during capture. A stopped K3s
server is not started by backup scheduling. A disposable restore drill remains
required; a successful timer or repository test is not restore evidence.

## Verification scope

`probe.yml`, `probe-wireguard.yml`, onboarding preflight, and `verify.yml` perform
their read-only checks even under `--check`; check mode does not silently skip
the inspection commands. Site check mode previews configuration without token
exchange, service activation, or Node patches.

`verify.yml` checks live WireGuard keys/peers/address/MTU/port/keepalives and the
applied fingerprint, live owned firewall evidence, Tailscale status, systemd
services, sysctls, and storage device/UUID/filesystem identity. The published
Flannel MTU must match `k3s_expected_pod_mtu` (`1370` by default: `1420` minus
IPv4 VXLAN overhead).

API readiness and Node reads delegate to `k3s_server_host`, including with
`task verify -- --limit <agent>`. Every **selected** node must be present, Ready,
and have exactly its configured WireGuard InternalIP. An unlimited run selects
the full mesh; a limited run does not require all inventory nodes to be Ready.
The delegated server must still be reachable. These checks do not replace
external ingress/NodePort tests, large cross-node TCP/UDP transfers, or reboot
and recovery drills.

## Datastore restore

`playbooks/restore-k3s.yml` is deliberately destructive and must run with
`--limit` equal to exactly one target hostname. Before running it:

- Stop or fence every other server. For multiple servers, explicitly set
  `K3S_RESTORE_PEER_RECOVERY_CONFIRMED=true` after reviewing the peer steps below.
- Make the target the designated init server: `k3s_server_init: true`, with both
  `k3s_cluster_init_host` and `k3s_server_host` naming it in inventory; every
  other server must be a joiner. Its installed configuration must also have no
  `server:` join URL and, for etcd, must contain `cluster-init: true`.
- Reconcile effective configuration, not just `config.yaml`: restore rejects
  symlinked configs, nonempty K3s config drop-in directories, substantive
  `/etc/default/k3s` environment content, `K3S_*` systemd-manager environment,
  unaccounted unit drop-ins/environment sources, and overridden `ExecStart` or
  startup conditions. Only the repository's exact recovery guard drop-in is
  accepted; the installed unit must run the expected binary and config path.
  The exact previous datastore-local guard drop-in is accepted during preflight
  so convergence or restore can replace it. Loaded-fence verification requires
  the new outside-datastore condition before state replacement or verified
  activation.
- Reconcile that topology before restoring onto a replacement init host. An
  etcd snapshot can come from another member, but that does not waive the target
  checks. SQLite recovery is node-bound and requires a single-server inventory.
- Controller and target must expose readable Linux `/proc/self/mountinfo`.
  Recovery rejects symlinked state trees and mounts anywhere at or beneath
  paths it recursively replaces or removes, including bind mounts. Mounting
  the whole `k3s_data_dir` is supported; separate mounts beneath `server/db`,
  `server/cred`, or `server/tls` require reviewed manual recovery. Keep external
  mount activity quiescent throughout recovery: repeated mount-table checks
  are not mount-namespace fencing.

The checksum sidecar must contain exactly one SHA256 record naming the selected
archive's basename: alternate filenames, paths, extra records, and trailing
content fail. The digest is calculated directly over that selected archive.
The play verifies decryption, exact archive members, and SQLite integrity on
the controller, then removes controller plaintext before remote operations.
It transfers a one-use age-encrypted copy; the long-term recovery
identity stays on the controller. Unique private staging directories isolate
runs. On the target it acquires the same lifecycle lock used by site, checks
effective configuration, backup identity, installed version, and topology, then
installs and verifies the persistent systemd startup inhibit before acquiring
the recovery guard. It stops backups/K3s and preserves original datastore, bootstrap
trees, and tokens before replacement. It installs the restored credentials and
uses `--cluster-reset --cluster-reset-restore-path` for etcd. Service/API and
expected-namespace checks gate target success.
The reset-only configuration explicitly binds the archived server token;
normal first initialization remains token-generating. Restore preserves the
service's existing boot-enablement setting, including when verification fails.

The persistent recovery inhibit is `/var/lib/cvp/k3s-restore-in-progress`
(`k3s_restore_guard_path` in host inventory). It must be an absolute path outside
the datastore, on persistent host storage that remains available independently
of the datastore mount. Installation creates a root-owned `0700` parent directory;
startup fails closed if that parent is missing or unsafe, or guard inspection
fails. While the inhibit exists, the systemd `ExecCondition` blocks ordinary
starts, including after reboot or loss of the datastore mount. Backups apply the
same inhibit-parent safety checks and reject guard inspection errors. Recovery
starts require the single-use `/run/cvp/k3s-restore-start` authorization: it is
consumed on use, expires within 60 seconds, and is bound to the current boot, guard identity, and
matching recovery/lifecycle owner. Unused authorization is revoked during
cleanup; it is not a persistent bypass.

Legacy `<k3s_data_dir>/.cvp-restore-in-progress` markers still block startup,
backups, convergence, and new restores. Inspect and resolve the original recovery
before migrating; changing the configured inhibit path or deleting a legacy
marker is not permission to bypass unresolved recovery. Keep the same host-scoped
inhibit setting for convergence, restore, and backup generation.

```sh
K3S_RESTORE_CONFIRM=true \
K3S_RESTORE_CONFIRM_HOST=server1 \
K3S_RESTORE_PEER_RECOVERY_CONFIRMED=true \
K3S_RESTORE_ARCHIVE=/secure/path/k3s-backup.tar.gz.age \
K3S_RESTORE_CHECKSUM=/secure/path/k3s-backup.tar.gz.age.sha256 \
K3S_RESTORE_AGE_IDENTITY=/secure/path/agekey.txt \
task restore-k3s -- --limit server1
```

**After successful etcd reset:** keep peers stopped until their join URLs point
at the target and their server/agent tokens match its restored files. Preserve
peer bootstrap material before reconciling it against the snapshot; newer local
credentials can prevent rejoin. Only then clear each peer's `server/db` and
rejoin one at a time. Reconcile agent tokens and verify the entire fleet. Target
success removes its staging/guard, resumes only previously active backup
scheduling, and releases lifecycle ownership after cleanup; it does not prove
peer recovery.

**After failed replacement and raw rollback:** keep original peer databases and
credentials. Raw rollback restores the old local trees/tokens; it is not a
cluster reset. Multi-server targets remain stopped for coordinated startup of
the original quorum; an originally active initialized standalone server may be
restarted. Preparation failures do not trigger destructive rollback. Once
acquired, `/var/lib/cvp/k3s-restore-in-progress` (or the configured host inhibit
path) remains after failure, including completed raw rollback, and blocks
backups/server convergence. Preserve the reported root-only plaintext material
in `/var/lib/rancher/k3s/.restore/<run>/`. Verify
manual recovery before removing the guard and explicitly resuming backups.
Failed recovery also retains any acquired `/var/lib/cvp/lifecycle.lock`, even
if failure precedes guard acquisition. Inspect and explicitly clean up only
after verifying no owner is still running and resolving the intended datastore/startup state;
neither lock nor guard may be stolen. A rollback failure requires resolving the
failed step before any startup.

Optional: `K3S_RESTORE_EXPECT_NAMESPACES` (comma-separated; default
`kube-system`) lists namespaces the restored datastore must contain, and
`K3S_RESTORE_ALLOW_VERSION_MISMATCH=true` bypasses the binary-version match
after a reviewed skew decision. A restore drill on disposable
infrastructure remains mandatory; a passing timer is not restore evidence.
