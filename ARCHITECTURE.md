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

All nodes remain schedulable; labels, taints, affinity, resource requests,
and limits define intentional placement.

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
through the Kubernetes API, but Ansible only removes taints recorded as its
own in the `cvp.io/managed-taints` Node annotation. Kubernetes/controller
taints are never cleared merely because they are absent from inventory.

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
- Tailscale ACLs, tags, and split-DNS policy.
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
or other ordinary Kubernetes resources. It may use `kubectl` only for the
one-time GitOps bootstrap or documented break-glass recovery.

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

The host firewall allows these cluster ports only on `wg0`:

| Port | Scope | Purpose |
| --- | --- | --- |
| TCP 6443 | agents and servers | Kubernetes API and K3s supervisor |
| TCP 2379 | servers | Embedded etcd client |
| TCP 2380 | servers | Embedded etcd peer traffic |
| UDP 8472 | all nodes | Flannel VXLAN |
| TCP 10250 | all nodes | Kubelet API and metrics |

Public WireGuard endpoints accept the mesh UDP port only from known peer
addresses where the provider permits stable filtering.

Because packets are encapsulated by both VXLAN and WireGuard, the implementation
must measure path MTU and set a verified pod MTU. Large cross-node TCP and UDP
transfers are an acceptance test, not an inferred property.

Kubernetes Services and CoreDNS provide internal service discovery. Databases
use Kubernetes Services directly.

## Control plane

K3s servers use embedded etcd by default. The operator selects server membership
and reviews quorum impact before adding or removing a server. A three-server
configuration tolerates one server failure; a single server does not.
The explicitly selected cluster-init server bootstraps etcd and
generates the shared server token, agent token, and secrets-encryption key.
Ansible distributes those files to the joining servers before their first
start, so all supervisors share the same credentials and encryption key.
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

The K3s etcd snapshot, the server and agent tokens, the node marker, and the
recorded K3s version are one recovery unit. All members are encrypted and
copied off-host. Application volume data is a separate recovery unit. Restore
stops the other servers, resets one target from the snapshot
(`k3s server --cluster-reset --cluster-reset-restore-path`), and the remaining
servers rejoin or are rebuilt from the surviving quorum; a disposable restore
drill is mandatory.

## Ingress and DNS

The operator selects the ingress node. It receives the K3s ServiceLB allow-list
label; the other nodes do not. Traefik's LoadBalancer service is restricted to
the ingress pool, so ports 80 and 443 are not occupied across the fleet.

The cluster network is intentionally IPv4-only, but public ingress arrives
over IPv6. Ansible bridges the two on the ingress node with systemd socat
forwarder units on the selected node: listeners on `[::]:80` and `[::]:443`
forward to `127.0.0.1:80` and `127.0.0.1:443`, where K3s ServiceLB and Traefik listen on
IPv4. The units are owned by the Ansible host layer role that manages the
ingress forwarders (see `ansible/roles/`), not by any Kubernetes resource.

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

1. Recreate a node from a clean supported OS/LXC using Ansible.
2. Recreate WireGuard and verify node connectivity.
3. Reinstall the pinned K3s version.
4. Restore the K3s datastore and matching server token, or build a clean cluster
   and let Flux reconstruct all non-data resources.
5. Restore persistent application data from R2.
6. Reconcile Git and run application smoke tests.

Backups are not accepted until a disposable restore drill passes.
