# Architecture

## Goals

1. Host applications reliably on operator-selected nodes with measured budgets.
2. Prefer a small, standard platform over custom control-plane software.
3. Use an operator-managed WireGuard node mesh.
4. Make a failed node or cluster recoverable from Git and off-host backups.
5. Keep every resource under one unambiguous owner.

## Non-goals

- Continuous availability after losing a node.
- A general-purpose PaaS product or portable application schema.
- Automatic workload placement outside Kubernetes.
- Distributed block storage.
- Highly available databases.
- A service mesh such as Istio or Linkerd.
- Custom Kubernetes operators or CRDs.

## Nodes

The default inventory contains no hosts and provisions none. The operator
chooses node count, server/agent roles, ingress placement, and storage intent.
`k3s_cluster_init_host` and `k3s_server_host` are empty by default; both must
identify an explicitly selected initial server before convergence. Only that
server has `k3s_server_init: true`.

Site validates the complete topology on the controller before host access, even
for a limited run. Server and agent groups exclusively partition the WireGuard
group, each node declares its matching role and boolean init flag, and exactly
one mesh node belongs to `ingress`. Mesh addresses are unique usable IPv4
addresses in one `/24`, public keys are unique, and all nodes agree on the init
host, designated server, datastore, and local-storage path. SQLite requires
exactly one server.

Persistent host settings and credentials are supplied through the external
`cvp/operator.yml` under `XDG_CONFIG_HOME` (default `~/.config`), or an explicit
`CVP_OPERATOR_CONFIG_FILE`. Host convergence and probes load its validated
`cvp_operator_defaults` and `cvp_operator_hosts` mappings before host access.
Connection and node identity remain in inventory; per-node credentials and
destructive confirmations cannot be distributed through operator defaults.
The file is literal data; only `wireguard_private_key` and `tailscale_auth_key`
accept `{env: NAME}` credential references. Onboarding pins the file digest or
its absence and checks API readiness and all existing inventory membership,
including roles, mesh addresses, and Ready state. Unexpected nodes, missing
existing nodes, and unconfirmed additional servers block onboarding. The check
is repeated under lifecycle locks before convergence.

For example, `server1` could initialize the cluster using the synthetic mesh
address `192.0.2.1`. These are documentation values, not provisioned resources.
Initial bootstrap uses the host bootstrap runbook; the onboarding helper adds
nodes only after the control plane exists.

Nodes may be LXC guests or ordinary VMs (`node_virtualization`: `lxc`, `vm`,
`metal`, or `auto` for probe-time detection). The compatibility probe applies
stricter shared-kernel checks to LXC guests: overlay must be a registered
filesystem and the required modules must already be loaded on the host,
because the guest cannot load them itself. VM and metal hosts only need the
modules available; the base role loads them and persists the loads across
reboots. The probe, the base role, and the verification playbook classify
environments with the same shared identifier lists, and a pinned declaration
that disagrees with the detected environment fails all three.

All nodes are intended to remain schedulable after bootstrap; labels, taints,
affinity, resource requests, and limits define intentional placement. New nodes
register with the reserved `cvp.io/bootstrap=true:NoSchedule` taint and
`cvp.io/bootstrap-quarantine=true` label. A single concurrency-checked API patch
per node applies desired labels and taints and removes the quarantine before
lifecycle ownership is released. These reserved keys cannot be set in inventory.

## Node tags and allocation

Tags are orthogonal boolean labels under `cvp.io/`:

| Tag | Meaning |
| --- | --- |
| `cvp.io/role=control-plane` | Every server. Not used for scheduling. |
| `cvp.io/compute=true` | Runs general application workloads. |
| `cvp.io/storage=true` | Holds local-path volumes and storage-backed workloads. |
| `cvp.io/stateful=true` | Accepts stateful services (databases, queues). |
| `cvp.io/ingress=true` | Serves public ingress (Traefik and ServiceLB). |
| `cvp.io/gpu=true` | Reserved capability tag; assigned only after accelerator hardware is actually attached. |
| `cvp.io/system=true` | Hosts small system workloads. |

Tags combine freely. A workload that needs storage and compute states both in
its node selector or affinity (`cvp.io/storage=true` AND `cvp.io/compute=true`
selectors all match); a workload that accepts either uses multiple
`nodeSelectorTerms`. Removing a tag from inventory reconciles it off the node,
affecting future scheduling; existing pods are not evicted by a node-label
change. Tag changes follow the same review path as ingress or storage
changes. Taints are optional per node (`k3s_node_taints`) and are reconciled
through the Kubernetes API. Apart from the reserved bootstrap quarantine,
Ansible only removes taints recorded as its own in the `cvp.io/managed-taints`
Node annotation. Kubernetes/controller taints are never cleared merely because
they are absent from inventory.

Ansible reconciles the `cvp.io/*` and `svccontroller.k3s.cattle.io/*` label
namespaces through the `kubernetes.core` collection; it does not manage other
node labels. The `cvp.io/role` label is derived from `k3s_role` and cannot be
declared per node, and `cvp.io/` accepts only the boolean catalog tags.
Additional custom label domains can be brought under reconciliation by
extending `k3s_managed_label_domains` with anchored, escaped literal DNS
prefixes (not arbitrary regular expressions). Every
declared label must match a managed domain — validation rejects it otherwise,
because a declared-but-unmanaged label would be applied without ever being
reconciled away — while labels already present on a node outside the managed
domains are never modified or removed.

## Ownership boundaries

### OpenTofu: external control planes

OpenTofu owns:

- Cloudflare zone records and provider-level policy.
- Tailscale ACLs, tag ownership, and split-DNS policy.
- Encrypted remote state for those resources.

It does not create Kubernetes resources or configure hosts.

### Ansible: host layer

Ansible owns:

- Administrative users, SSH, sudo, packages, and time synchronization.
- Required kernel modules, sysctls, cgroups, and LXC compatibility checks.
- Host firewall policy.
- Tailscale installation and enrollment.
- WireGuard keys, peers, addresses, routes, and public endpoint rules.
- Disk formatting, mounts, and directories required before K3s starts.
- Pinned K3s installation and node configuration.
- K3s datastore and token backup because those exist below Kubernetes.
- The host-side prerequisites for Flux bootstrap, but not Flux or SOPS secrets.

Ansible does not apply application, database, ingress, certificate, monitoring,
or other ordinary Kubernetes resources. It uses the Kubernetes API for Node
reconciliation and read-only health checks, including delegated `kubectl`
readiness checks. Imperative workload changes remain confined to documented
bootstrap or break-glass recovery.

Site acquires `/var/lib/cvp/lifecycle.lock` on the full selected host set before
host convergence. Mutating `--limit` selections must include
`k3s_cluster_init_host` so the shared API/credential dependency is locked. Every
phase uses `any_errors_fatal`; ownership is released only after successful Node
reconciliation. Restore uses the same lifecycle lock. Failed operations retain
their locks without automatic expiry or stealing. Operators must inspect the
state, verify no owner is still running, and resolve recovery before explicit
cleanup.

When operator-account management is enabled, Ansible owns its complete SSH
authorized-key set and removes omitted keys. SSH hardening is checked against
effective daemon settings. WireGuard rotation requires a new matching key pair
and an explicit host confirmation; peer updates are coordinated maintenance,
not an atomic or uninterrupted-service operation.

Journald, SSH, and IPv6 ingress activation records bind configuration fingerprints
to systemd invocation IDs after successful activation; ingress also checks that
the expected process owns its listener. Failed activation leaves no success
record, allowing a later run to retry unchanged pending configuration.

### K3s and Flux: cluster layer

K3s and Flux own:

- CoreDNS, Traefik, ServiceLB, and Kubernetes network policy.
- Namespaces, service accounts, RBAC, quotas, and limit ranges.
- Certificates, ingress, services, applications, Jobs, and CronJobs.
- PersistentVolumeClaims and workload placement declarations.
- Database and queue workloads when an application actually needs them.
- Monitoring, alerting, and in-cluster backup jobs.
- Deployment, rollback, retirement, and deletion through ordinary Kubernetes
  resources and Git history.

Direct imperative `kubectl apply` is reserved for bootstrap or incident
recovery. Normal changes arrive through Flux.

The operator-owned `task bootstrap-flux` boundary seeds the Flux deploy key and
SOPS age identity directly into the cluster. Ansible never owns those secrets.

## Network model

```text
Internet
  -> Cloudflare DNS/proxy
  -> selected ingress node public IPv6:80/443
  -> socat forwarders to 127.0.0.1:80/443
  -> K3s ServiceLB
  -> Traefik
  -> Kubernetes Service
  -> Pod

Operator
  -> Tailscale
  -> SSH, Kubernetes API, and temporary port-forward access

Node and pod traffic
  -> wg0 (operator-selected mesh; example 192.0.2.0/24)
  -> Flannel VXLAN
  -> remote pod or service
```

WireGuard is the node underlay, not an application service mesh. K3s nodes use
their operator-assigned mesh addresses as internal node addresses. Flannel uses
`wg0` as its interface and the VXLAN backend, avoiding a second WireGuard layer.

WireGuard convergence uses `wg syncconf` on the live interface, with in-place
address/MTU reconciliation, instead of restarting `wg-quick` or its K3s
dependents. The supported shape is the repository's single IPv4 `/24` with peer
`/32` routes inside it; interface identity/address migrations and unsupported
configuration require explicit coordinated maintenance. Unchanged endpoint
intent preserves authenticated roaming; changed endpoint intent is applied.
Live verification accepts dynamic learned/resolved endpoints rather than
requiring equality to the configured hostname or address, while checking the
keys, peers, AllowedIPs, keepalives, port, MTU, address, and applied fingerprint.
It also requires the kernel-connected mesh `/24` route, including with no peers,
and direct effective routes to every peer. Route drift on an active interface
requires explicit maintenance; absent/down interfaces are checked after startup
or in-place recovery before successful activation is recorded.

The host firewall permits these node-to-node cluster paths on `wg0`:

| Port | Scope | Purpose |
| --- | --- | --- |
| TCP 6443 | agents and servers | Kubernetes API and K3s supervisor |
| TCP 2379 | servers | Embedded etcd client |
| TCP 2380 | servers | Embedded etcd peer traffic |
| UDP 8472 | all nodes | Flannel VXLAN |
| TCP 10250 | all nodes | Kubelet API and metrics |

Tailscale separately permits SSH and API access, plus ingress testing on ingress
nodes; pods can reach the API and kubelet through their configured pod CIDR.
WireGuard endpoint source allowlists default to all sources, with peer keys
providing authentication. Narrow the allowlists to stable peer endpoints when
available.

Firewall administration preflight requires either an explicit source CIDR
matching the current SSH client or exact established-socket kernel binding to
the private interface and a direct matching return route. Stock unbound sshd
therefore needs a host-scoped `/32` or `/128`, including the client's Tailscale
source address for ordinary private SSH. If session metadata is unavailable,
an independently verified source CIDR remains mandatory. Backend `Running`
and private destination addresses alone cannot authorize activation.

The firewall identifies IPv4 and IPv6 public uplinks separately. New external
forwarding is allowed only for DNAT traffic whose original destination is an
ingress uplink address and approved TCP port, preserving established and private
cluster paths. This complements input filtering; pod-directed DNAT traffic
bypasses host INPUT. nftables reload and stop operations affect only the owned
`cvp_filter` table.

Convergence records the applied configuration hash and live owned-table state;
read-only verification detects a missing or changed table and unapplied files.
Probes and verification still perform read-only checks under `--check`.
Verification delegates API readiness and Node reads to `k3s_server_host`, even
with an agent-only limit, and requires only selected nodes to be Ready with
their exact mesh InternalIP.

Kube-proxy uses iptables mode and restricts NodePort addresses to IPv4 loopback,
the node's exact WireGuard IPv4 address, and `::1/128`; specifying the IPv6 family
avoids an implicit wildcard. LoadBalancer NodePort allocation remains enabled
because ServiceLB with `externalTrafficPolicy: Local` needs it. Public exposure
is constrained by both this address selection and the host forwarding policy.

Because packets are encapsulated by both VXLAN and WireGuard, the implementation
must measure path MTU and set a verified pod MTU. Large cross-node TCP and UDP
transfers are an acceptance test, not an inferred property.

Kubernetes Services and CoreDNS provide internal service discovery. Databases
use Kubernetes Services directly.

## Control plane

K3s servers use embedded etcd by default. The operator selects server membership
and reviews quorum impact before adding or removing a server. A three-server
configuration tolerates one server failure; a single server does not.
The explicitly selected cluster-init server bootstraps etcd. K3s generates its
server token and secrets-encryption configuration; Ansible provisions the
dedicated agent token and copies the server/agent tokens to joining servers.
K3s itself distributes secrets-encryption material through datastore bootstrap;
Ansible does not manually copy the encryption configuration.
Loss of quorum requires etcd recovery procedures. A deliberate single-server
setup may instead use SQLite. Ansible does not run `kubectl` for node settings;
labels and taints are reconciled with the `kubernetes.core` modules.

The K3s configuration must:

- Pin an explicitly reviewed K3s version.
- Set the node IP and advertised address to the WireGuard address.
- Use `wg0` as the Flannel interface.
- Enable Kubernetes secret encryption at rest.
- Include only required API TLS subject alternative names.
- Keep packaged CoreDNS, Traefik, ServiceLB, metrics-server, and network policy
  unless a measured problem justifies replacing one.

The K3s snapshot, server and agent tokens, node marker, and serving binary's
version form one encrypted recovery unit. Backup-enabled servers publish unique
bundles containing the archive and its checksum; both must be copied off-host.
Backup enablement is persistent operator configuration. Disabling an enabled or
busy backup schedule requires a host-specific confirmation. Application volume
data remains a separate recovery unit.
An on-host backup-identity ledger binds the timer, service, and script names;
renaming them fails closed until the old units and ledger are explicitly migrated.

Before restore, the operator stops or fences other servers and reconciles the
target as the designated init server in both inventory and installed config.
Restore validates effective systemd execution and K3s configuration sources,
rejecting unaccounted drop-ins, environment inputs, and command overrides. Its
checksum sidecar must contain exactly one SHA256 record for the selected archive
basename. The play validates the archive on the controller, uses one-use
encrypted remote transport, preserves original state, then resets the target
from the snapshot.
After success, peers need the restored credentials and correct join URLs before
their databases are cleared and they rejoin. Raw rollback instead preserves the
original peer databases and credentials for original-quorum recovery. Failed
transactions retain their guard and recovery material for explicit resolution.
The persistent restore guard inhibits systemd startup, including after reboot.
An authorized recovery start consumes a single-use `/run` authorization bound to
the current boot, guard identity, and common lifecycle owner, expiring within
60 seconds. Recovery preserves the service's existing boot-enablement setting.

## Ingress and DNS

The operator selects the ingress node. It receives the K3s ServiceLB allow-list
label; the other nodes do not. Traefik's LoadBalancer service is restricted to
the ingress pool, so ports 80 and 443 are not occupied across the fleet.

The cluster network is intentionally IPv4-only, but public ingress arrives
over IPv6. Ansible bridges the two on the ingress node with systemd socat
forwarder units on the selected node: listeners on `[::]:80` and `[::]:443`
forward to `127.0.0.1:80` and `127.0.0.1:443`, where K3s ServiceLB and Traefik listen on
IPv4. The units are owned by the Ansible host layer role that manages the
ingress forwarders (see `ansible/roles/`), not by any Kubernetes resource. They
run unprivileged with bind-service capability and bounded children, tasks, and
memory. Public IPv4 reaches ServiceLB directly.

The limitations of this frontend are accepted deliberately: the IPv6 path is
a plain TCP proxy, so IPv6 client source addresses are not preserved
end-to-end, and no PROXY protocol is used because the IPv4 direct path
cannot carry PROXY-protocol headers and the two paths cannot be mixed. Full
dual-stack networking remains a possible future change.

Cloudflare records point public names at the selected ingress node. This is not
advertised as highly available. Moving ingress is a documented recovery action
that updates the node label and DNS.

Private administration uses Tailscale and `kubectl port-forward` by default.
An in-cluster SSO and private-dashboard ingress plane is added only when a real
application requires browser access by more than the owner.

## Storage and data services

K3s local-path storage is the initial StorageClass. Stateful workloads are
pinned to operator-selected storage nodes; their volumes do not move automatically
after node loss. Recovery restores them on a replacement or surviving node from
off-host backup.

Host storage checks device identity, unique UUID, filesystem, and mount layout
before mutation. Automatic formatting is limited to an all-zero ext4 candidate
with both format opt-ins and the exact host/device/hash confirmation from
preflight. Existing ext4/XFS mounts must pass identity checks. Populated-directory
migrations, device mappings, conflicting mounts, and ambiguous disk ownership
require manual preparation; the role does not move application data.
Probes are bounded to 15 seconds, whole-device zero scans to 300 seconds, and
each inspection to 600 seconds with a five-second kill grace period, including
in check mode. Timeouts fail closed; large or slow devices require external
preparation.

All mesh nodes share one `k3s_default_local_storage_path`. On every
storage-enabled node, `storage_mountpoint` must equal that path (default
`/var/lib/rancher/k3s/storage`); heterogeneous per-node mount paths are not
supported by this local-path configuration.

Rules:

- Use Cloudflare R2 directly when object storage is required.
- Install PostgreSQL only when an application requires it.
- Start PostgreSQL as one instance, not an HA cluster.
- Prefer a dedicated Redis or queue per application over a shared multi-tenant
  service while the application count is small.
- Do not install RabbitMQ, Redis, or an operator preemptively.
- Require application-native consistent backups before accepting persistent
  production data.

An operator such as CloudNativePG is permitted only after a short design spike
proves that it reduces backup and restore work compared with a plain StatefulSet.
It must remain single-instance under the initial availability model.

## Secrets

- An operator-chosen external secrets store holds host, recovery, and OpenTofu
  credentials; Bitwarden Secrets Manager is one optional example.
- Cluster Secrets are encrypted in Git with SOPS and age.
- Flux decrypts only Secret data immediately before applying it.
- The age private key is stored in that external secrets store and injected
  into `flux-system` during bootstrap; it is never committed.
- K3s encrypts Kubernetes Secrets in its datastore.
- Workloads receive only explicitly referenced Secrets and never receive
  external-store, SOPS, age, Flux, or infrastructure credentials.

This avoids a permanent secret-synchronization controller while preserving an
off-cluster recovery copy of the decryption key.

## GitOps structure

The Git source ships with an `example.invalid/repository.git` placeholder in
`cluster/flux-system/source.yaml`. The operator must replace it with the reviewed
repository URL and set `FLUX_GITHUB_OWNER` and `FLUX_GITHUB_REPOSITORY` explicitly
when bootstrapping Flux.

Flux reconciliation is ordered:

1. Namespaces and policy.
2. Sources and cluster-wide controllers.
3. Storage, certificates, and ingress configuration.
4. Data services.
5. Applications.
6. Monitoring and backup jobs.

Kustomize is the default packaging mechanism. HelmRelease is used for upstream
software that already publishes a maintained chart. Locally invented charts
are prohibited unless plain manifests become demonstrably unmaintainable.

Images use immutable digests in production. Resource requests, limits,
readiness probes, security contexts, and a default-deny NetworkPolicy are
required before an application is classified as production-ready.

## Observability

Start with:

- K3s metrics-server.
- Kubernetes events and container logs.
- Flux reconciliation status and alerts.
- External HTTP uptime checks.
- Host-level disk, backup, and WireGuard health checks.

Do not install a metrics database, dashboard suite, or log aggregation stack
until concrete retention and query requirements exist. If added, it must fit a
measured node budget and remain removable without affecting workloads.

## Recovery model

The required recoveries are:

1. Recover persistent operator configuration and recreate a node from a clean
   supported OS/LXC using Ansible.
2. Recreate WireGuard and verify node connectivity.
3. Reinstall the pinned K3s version.
4. Restore the K3s datastore and matching server token, or build a clean cluster
   and let Flux reconstruct all non-data resources.
5. Restore persistent application data from R2.
6. Reconcile Git and run application smoke tests.

Backups are not accepted until a disposable restore drill passes.
