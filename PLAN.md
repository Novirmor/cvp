# Development Plan

## Delivery policy

The repository starts with an empty inventory and no provisioned hosts. The
operator supplies inventory, selects the initial server explicitly, and reviews
configuration before bootstrap. `k3s_cluster_init_host` and `k3s_server_host`
default to empty. Examples use `server1` and synthetic `192.0.2.*` mesh addresses.

Destruction of a host, provider resource, secret, or data volume requires a
review that names the affected resource and verifies its recovery or accepted
loss.

Each milestone finishes with executable evidence. A file existing in Git is not
deployment evidence.

A ticked item is implemented in this repository and covered by the
credential-free checks (`task lint`, `task test`, `task security`, and the
isolated dataplane tasks). No item that requires a live host, cluster, provider
account, or restore drill is ticked, and no exit gate has been passed yet.

## M0: Repository foundation

### Deliverables

- [x] Pin the complete local toolchain in `mise.toml`: Ansible, OpenTofu,
  kubectl, Helm, Flux, Kustomize, SOPS, age, Task, and security linters.
- [x] Add one local CI workflow that runs `task lint`, `task test`, and
  `task security`; do not create another reusable-workflow repository.
- [x] Add YAML, Ansible, Kubernetes, shell, OpenTofu, action, and secret linting.
- [x] Define naming and labels once for nodes, namespaces, applications, and
  backup objects.
- [x] Add Renovate or Dependabot for container, Helm, action, and tool pins.

### Exit gate G0

- A fresh checkout installs its tools and passes every credential-free check.
- Local workflows are self-contained and use pinned dependencies.

## M1: Host and network proof

### Deliverables

- [ ] Record the capabilities of each selected host: kernel, cgroup v2,
  overlayfs, VXLAN, iptables/nftables, mount propagation, AppArmor, and required
  device access.
- [ ] Prove containerd can create, stop, and restart a pod after host reboot.
- [ ] Prove configured WireGuard peers reconnect after reboot.
- [ ] Run K3s on one disposable node with `node-ip` on `wg0`.
- [ ] Run Flannel VXLAN over `wg0` and determine a safe pod MTU.
- [ ] Verify large TCP and UDP transfers without fragmentation failures.
- [ ] Verify DNS, Service routing, exec, logs, and metrics-server.
- [ ] Create, remount, and delete a local-path PVC.
- [ ] Record the exact K3s version accepted by the proof.

### Exit gate G1

- The tested host supports K3s without provider-side changes that cannot be
  reproduced.
- The tested MTU and firewall rules survive reboot.
- A failed proof stops bootstrap and triggers a hosting or architecture
  decision; it is not worked around with an undocumented privilege increase.

## M2: Minimal Ansible host layer

### Deliverables

- [x] Keep default inventory empty; document operator-supplied K3s roles,
  WireGuard addresses, public endpoints, Tailscale addresses, and storage intent.
- [x] Implement local roles: `base`, `firewall`, `tailscale`, `wireguard`,
  `storage`, `k3s_server`, and `k3s_agent`.
- [x] Use local roles and pinned public Ansible collections.
- [ ] Pin package sources and K3s artifacts; verify checksums or signatures.
- [x] Make WireGuard converge before K3s.
- [x] Bind K3s node traffic to `wg0` and prevent cluster ports on public
  interfaces.
- [x] Add a read-only host verification playbook.
- [ ] Add an idempotence check and reboot-persistence test.
- [x] Implement a host-level encrypted backup for the K3s datastore (embedded
  etcd snapshot, or SQLite in single-server mode) and the matching server and
  agent tokens.

### Exit gate G2

- Ansible builds a clean node using repository-local roles and pinned dependencies.
- A second run is idempotent apart from explicitly documented probes.
- Host verification proves SSH, Tailscale, WireGuard, firewall, disks, and K3s
  service health.

## M3: Operator-configured K3s cluster

### Deliverables

- [ ] Explicitly select the initial server (example `server1`) in
  `k3s_cluster_init_host` and `k3s_server_host`, and set its
  `k3s_server_init: true` before initial host bootstrap.
- [ ] Initialize the selected K3s server with embedded etcd (`cluster-init`).
- [ ] Add subsequent servers or agents with `task node-join` over the
  selected server's mesh address (example `192.0.2.1:6443`), reviewing quorum
  impact for each server addition.
- [ ] Label nodes with the boolean `cvp.io/*` allocation tags (`compute`,
  `storage`, `stateful`, `ingress`, `system`) reconciled through the
  Kubernetes API.
- [ ] Enable K3s secret encryption at rest.
- [ ] Restrict ServiceLB to the operator-selected ingress pool.
- [ ] Configure and test CoreDNS and Traefik using packaged K3s components.
- [ ] Spread critical DNS replicas so ordinary pod traffic is not needlessly
  tied to one node.
- [ ] Define resource reservations so system components retain headroom.
- [ ] Capture a baseline of idle CPU, memory, disk, and WireGuard traffic.

### Exit gate G3

- Pods communicate across every node pair through the WireGuard underlay.
- A public test route enters only through the ingress node.
- Restarting each server preserves the expected workloads and networking.
- Quorum behavior for the selected server count and recovery after quorum loss
  are documented and rehearsed.

## M4: Flux and secret bootstrap

### Deliverables

- [ ] Replace the `example.invalid/repository.git` placeholder in
  `cluster/flux-system/source.yaml` with the reviewed repository URL and branch.
- [ ] Bootstrap Flux with a read-only deploy key, explicitly supplying
  `FLUX_GITHUB_OWNER` and `FLUX_GITHUB_REPOSITORY`.
- [x] Define ordered Flux Kustomizations for policy, infrastructure, data, apps,
  and operations.
- [x] Enable pruning and drift correction.
- [ ] Recover or generate one age key for the cluster, store its private half in
  an operator-chosen external secrets store, and seed it into `flux-system` through
  `scripts/bootstrap-flux`; Ansible never owns this key.
- [ ] Add `.sops.yaml` rules that encrypt only Secret payloads.
- [ ] Prove that Git contains no plaintext secret and Flux can restore an
  encrypted test Secret after deletion.
- [x] Document a break-glass Flux suspend, reconcile, and recovery procedure.

### Exit gate G4

- Rebuilding an empty cluster and bootstrapping Flux reconstructs all non-data
  cluster resources from Git.
- Removing a managed test object is corrected by Flux.
- A machine without the age private key cannot decrypt committed Secrets.

## M5: Cluster security baseline

### Deliverables

- [ ] Create namespaces for infrastructure, operations, and each application.
- [ ] Apply Pod Security Admission labels using the restricted profile by
  default and narrowly document exceptions.
- [ ] Add default-deny ingress and egress NetworkPolicies per namespace.
- [ ] Add DNS and explicitly required dependency egress rules.
- [ ] Add LimitRanges and ResourceQuotas.
- [ ] Require non-root execution, seccomp RuntimeDefault, dropped capabilities,
  read-only root filesystems where possible, and bounded temporary storage.
- [ ] Define minimal service accounts and RBAC.
- [ ] Validate manifests against the exact cluster Kubernetes version.
- [x] Add policy tests for prohibited host networking, host paths, privileged
  containers, mutable production tags, and unbounded resources.

### Exit gate G5

- A deliberately non-compliant workload is rejected before merge and cannot run
  when applied manually.
- A test namespace cannot contact another namespace until policy allows it.

## M6: Public ingress, DNS, and certificates

### Deliverables

- [x] Maintain separate Cloudflare and Tailscale OpenTofu roots in `tofu/` without
  combining their state with Kubernetes or application state.
- [ ] Review external resource ownership before applying; import resources when
  adopting objects already managed outside these roots.
- [ ] Point a disposable hostname at the selected ingress node.
- [x] Configure Traefik through a Git-managed K3s `HelmChartConfig`.
- [ ] Deploy cert-manager only if Traefik's maintained K3s configuration cannot
  satisfy the required certificate lifecycle cleanly.
- [ ] Use a scoped Cloudflare token for DNS-01 when DNS-01 is required.
- [ ] Verify HTTP-to-HTTPS redirect, certificate renewal, client IP handling,
  request limits, and ingress resource isolation.
- [x] Write the ingress relocation procedure for moving traffic to another node.

### Exit gate G6

- A disposable public application serves a valid certificate through Cloudflare
  and Traefik.
- Only the ingress node accepts public ports 80 and 443.
- The relocation procedure is tested without changing application manifests.

## M7: Storage, backup, and recovery

### Deliverables

- [ ] Validate local-path storage directories, ownership, disk capacity, and
  node affinity on the selected storage nodes.
- [ ] Select one encrypted R2 backup mechanism and remove parallel backup paths.
- [ ] Back up the K3s datastore and token below the cluster.
- [ ] Define a Kubernetes CronJob pattern for application-native dumps and file
  backups.
- [ ] Export backup success, age, size, and last-restore metrics or checks.
- [ ] Define retention and lifecycle rules in R2.
- [ ] Build a disposable restore environment.
- [ ] Restore the control plane from backup.
- [ ] Restore a PVC and an application-native database dump.
- [ ] Measure and record recovery time and recovery point.

### Exit gate G7

- A complete restore succeeds using maintained repository runbooks.
- Backup monitoring detects missing, empty, stale, and corrupt backup sets.
- The server token and datastore are proven to be a matched recovery unit.

## M8: First application

### Deliverables

- [ ] Build the example site image in its application repository and push it to
  GHCR.
- [ ] Pin the production Deployment to an image digest.
- [ ] Add Namespace, Deployment, Service, Ingress, NetworkPolicy, requests,
  limits, probes, and security context using ordinary Kubernetes resources.
- [ ] Deploy staging and production as explicit overlays only if both are still
  useful.
- [ ] Add an external uptime check and a post-deployment smoke test.
- [ ] Exercise rollout, failed rollout, rollback, deletion, and recreation.

### Exit gate G8

- The application is fully reproducible from its image, this repository, and
  the cluster secret recovery key.
- Standard Kubernetes resources and Flux implement application deployment.

## M9: Data services on demand

### PostgreSQL decision spike

- [ ] Compare a plain single-instance StatefulSet with single-instance
  CloudNativePG for upgrade, backup, recovery, and resource cost.
- [ ] Select the smaller operational model based on a restore demonstration.
- [ ] Provision one test database and least-privilege role.
- [ ] Back up to R2 and restore into a clean namespace.
- [ ] Define application migration ownership; schema migrations belong to the
  application release, not the infrastructure controller.

### Other services

- [ ] Deploy Redis only for an identified application and prefer an app-scoped
  instance over shared ACL tenancy.
- [ ] Deploy RabbitMQ only for an identified durable queue requirement.
- [ ] Apply the same resource, policy, backup, and restore gates to every
  stateful service.

### Exit gate G9

- The first stateful application has a tested data restore and cannot access
  another application's namespace or credentials.
- Every deployed data service has an identified application requirement.

## M10: Minimal operations

### Deliverables

- [ ] Keep metrics-server and Kubernetes events as the initial diagnostic layer.
- [ ] Send Flux failures, backup failures, and external uptime failures to one
  off-cluster notification destination.
- [ ] Add host checks for disk pressure, WireGuard handshake age, K3s service
  health, and backup age.
- [ ] Define log retention limits for containerd and systemd journals.
- [ ] Run a two-week baseline before selecting a metrics database.
- [ ] If the baseline proves a need, evaluate a single small metrics stack with
  a fixed memory and retention budget; do not add distributed logging by
  default.

### Exit gate G10

- Node loss, failed reconciliation, failed backup, certificate failure, and
  public endpoint failure produce actionable off-cluster notifications.
- Observability remains within the measured resource budget.

## M11: Operator readiness

### Deliverables

- [ ] Rehearse initial bootstrap from empty inventory using explicit operator inputs.
- [ ] Rehearse subsequent node onboarding and a reviewed node removal.
- [ ] Run a clean-machine operator drill covering deployment, diagnosis, backup,
  and restore using maintained runbooks.

### Exit gate G11

- Initial bootstrap and subsequent onboarding are independently documented and tested.
- A clean-machine operator can deploy, diagnose, back up, and restore using
  explicit inventory, external secrets, and maintained runbooks.

## Deferred until justified

- Distributed persistent storage.
- Multiple ingress nodes or paid Cloudflare load balancing.
- Automatic image promotion.
- Tailscale Kubernetes Operator.
- External secret-synchronization operators.
- Metrics and log aggregation suites.
- Database, Redis, or RabbitMQ high availability.
- Multi-cluster management.
