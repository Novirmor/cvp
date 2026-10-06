# Cluster Layer

This directory is the desired state for a clean-slate K3s cluster. Normal
changes are reconciled by Flux. The repository does not define application
manifests, CRD schemas, operators, or private keys.

## In an instance repository

An instance (created with `task new-instance`) carries its own
`cluster/flux-system/`: the Flux components copied from the pinned platform, its
own `flux-system` source, a `cvp-platform` source pinned with `ref.commit` to
the `platform/` submodule commit, and a reconciliation graph in which `policy`,
`infrastructure`, `data`, and `operations` come from `cvp-platform` while
`apps` comes from the instance. Validation (`task validate` in the instance,
and the Flux bootstrap preflight) renders and policy-checks the platform layers
from that exact commit; an unpinned, mismatched, authenticated, or filtered
`cvp-platform` source is rejected. The bootstrap preflight additionally
requires the published instance commit's `platform` submodule pointer and the
local checkout to equal the pin. Flux's revision for a commit-pinned source is
`sha1:<commit>`; bootstrap readiness expects platform layers at that revision.
Instance-specific additions (secrets, extra namespaces) belong in Kustomizations
sourced from the instance.

## Layout

```text
flux-system/                  Flux source and ordered Kustomizations
infrastructure/policy/        Namespaces, PSA labels, quotas, limits, policy
infrastructure/ingress/       K3s packaged Traefik HelmChartConfig
data/                          Empty, suspended stateful-service layer
apps/example/                  Ordinary Kubernetes smoke application base
apps/overlays/smoke/           Suspended, opt-in non-production overlay
operations/                    Suspended backup and backup-check templates
secrets/                       SOPS/age instructions and placeholders only
```

Flux v2.5.1 components and their upstream CRDs are committed in
`flux-system/gotk-components.yaml`, sourced from the official release asset.
The local manifest pins Flux's namespace PSA warning label to `v1.35`.
`HelmChartConfig` is the existing K3s packaged-chart configuration API; this
repository does not install or define that CRD.

## Apply Order

No live cluster changes are performed by repository validation. Use a real
context only after reviewing the rendered output.

1. Bootstrap the first host and any later nodes with `task node-new`,
   `task node-bootstrap`, and `task node-join` (`docs/runbooks/nodes.md`); the
   first node is selected in `k3s_cluster_init_host` and `k3s_server_host`. Confirm API access, CoreDNS, packaged Traefik, ServiceLB, and the
   configured WireGuard addresses are healthy.
2. Restrict K3s ServiceLB to the ingress pool. Label only the ingress node with
   both `svccontroller.k3s.cattle.io/enablelb=true` and
   `svccontroller.k3s.cattle.io/lbpool=public`; verify that other nodes carry
   neither label. It must also have `cvp.io/ingress=true` for Traefik; the
   smoke app itself schedules on any `cvp.io/compute=true` node.
3. Recover or generate the cluster age identity out of band and store its
   private half in an operator-chosen external secrets store. An operator seeds
   `sops-age`; Ansible does not create or recover this Secret. See
   [`secrets/README.md`](secrets/README.md).
4. Replace the `example.invalid/repository.git` placeholder in
   `flux-system/source.yaml` with the reviewed repository URL and review the
   branch. Set `FLUX_GITHUB_OWNER` and `FLUX_GITHUB_REPOSITORY` explicitly to
   match that URL (`ssh://git@github.com/<owner>/<repository>.git`). Replace
   the example owner and repository below. Commit and push all `cluster/`
   changes to the configured branch before running the helper. Its SSH preflight
    fetches that branch with the reviewed deploy key and known_hosts file, compares
    actual cluster file bytes with the fetched commit (including files hidden by
    Git index flags), and validates a private, commit-addressed snapshot before
    contacting Kubernetes. All bootstrap applies and the ingress check use that
    snapshot. The fetched source URL and branch must match the reviewed inputs.
    Then use an explicit context with the temporary
   deploy key and recovered age identity:

     ```sh
     FLUX_GITHUB_OWNER=example-owner \
     FLUX_GITHUB_REPOSITORY=example-repository \
     FLUX_KUBE_CONTEXT=reviewed-cluster-context \
     FLUX_GIT_SSH_KEY_FILE=/path/to/deploy-key \
     FLUX_GIT_KNOWN_HOSTS_FILE=/path/to/known-hosts \
     SOPS_AGE_KEY_FILE=/path/to/recovered/age.key \
       task bootstrap-flux
     ```

5. Verify the ordered Flux Kustomizations. The root `flux-system`
   Kustomization owns the source and every child Kustomization. `policy`
   gates `infrastructure` and the reserved, suspended `data` layer;
   `infrastructure` gates the suspended `apps` smoke layer and `operations`.
   The root itself runs with `wait: false` and health checks on the six Flux
   controller Deployments, so suspended children that never reconcile cannot
   block root readiness on a fresh bootstrap. Infrastructure also uses
   `wait: false`, so its explicit Traefik Deployment health check is honored.
   Other active children use their own wait. The bootstrap helper additionally
    requires the source artifact and every active child to be Ready at the verified
    commit and current generation, with reconciliation enabled. It also checks the
    deployed packaged chart version and values, completed K3s chart
   Job, Traefik rollout, and Ready ServiceLB/local pod endpoints on the selected
   ingress node. Repeat this read-only gate after any ingress change:

   ```sh
   flux get sources git -n flux-system
   flux get kustomizations -n flux-system
   kubectl -n flux-system get events --sort-by=.lastTimestamp
    python3 scripts/cluster-ingress-ready --context reviewed-cluster-context --timeout 5m
    ```

    Keep the published branch unchanged during bootstrap. Branch changes are
    checked before applies and around readiness collection, including after the
    ingress check; a race fails bootstrap without undoing completed applies.
    Bootstrap rejects source filters/includes, `.sourceignore`, cluster symlinks,
    and transformations of the four directly applied bootstrap manifests. Move
    such changes into the direct manifests and keep Flux paths inside `cluster/`.

6. Keep `data`, `apps`, and both operations CronJobs suspended until the
   corresponding service, image, secret, egress, and recovery review is
   complete. The current example app is only a smoke template and uses the
   placeholder host `example.invalid`.

Before applying, render every changed overlay locally:

```sh
kubectl kustomize cluster
kubectl kustomize cluster/infrastructure/policy/overlays/cluster
kubectl kustomize cluster/infrastructure/ingress/overlays/k3s
kubectl kustomize cluster/apps/overlays/smoke
kubectl kustomize cluster/operations/overlays/cluster
```

## Recovery Order

1. Preserve the incident evidence and pause destructive operations.
2. Rebuild the host and WireGuard layer with Ansible. Restore the K3s etcd
   snapshot and the matching tokens together, or intentionally build a clean
   K3s cluster when the datastore recovery unit is unavailable. A multi-server
   restore stops the other servers first and runs the restore on one target;
   the remaining servers rejoin or are rebuilt per the runbook.
3. Reinstall the pinned K3s version and verify API access, CoreDNS, ServiceLB,
   Traefik, cross-node pod networking, and both ServiceLB labels on the ingress
   node: `svccontroller.k3s.cattle.io/enablelb=true` and
   `svccontroller.k3s.cattle.io/lbpool=public`.
4. Restore the read-only Git deploy key and `sops-age` identity from the
   operator-chosen external secrets store.
   An operator manually seeds both through `scripts/bootstrap-flux`; Ansible
   does not own or reconstruct either private key.
5. Run `task bootstrap-flux` with explicit `FLUX_GITHUB_OWNER`,
   `FLUX_GITHUB_REPOSITORY`, and the recovery context, as in the bootstrap
   example. It installs
   the committed Flux components and waits for Flux, policy, infrastructure,
   and operations to become Ready before enabling an application layer.
6. Restore persistent application data from the off-cluster backup and verify
   checksums and application-native consistency. Local-path PVCs do not move or
   restore themselves after node loss.
7. Reconcile the required data and app overlays, run HTTP and application smoke
   tests, and verify backup/check Job evidence.
8. If the ingress node changed, move ingress as one sequenced change. Update
   both the Traefik placement label `cvp.io/ingress=true` and the ServiceLB
   labels `svccontroller.k3s.cattle.io/enablelb=true` and
   `svccontroller.k3s.cattle.io/lbpool=public` together through the Ansible
   inventory and label reconciliation, removing them from the old node.
   Verify that the Traefik pod actually rescheduled to the new node and that
   the svclb-traefik DaemonSet has a ready pod with a local endpoint there;
   `externalTrafficPolicy: Local` requires the ingress node to run Traefik
   itself. The pinned K3s ServiceLB forwards local traffic through the allocated
   Service NodePorts, so `allocateLoadBalancerNodePorts` must remain true.
   Only then cut over the external DNS target and verify the public
   route before declaring recovery. The smoke workload's
   `cvp.io/compute=true` affinity follows the surviving labeled nodes
   when recovering from node loss.

ServiceLB DaemonSets have a Service-UID suffix; discover them with both
`svccontroller.k3s.cattle.io/svcname=traefik` and
`svccontroller.k3s.cattle.io/svcnamespace=kube-system`, not an exact
`svclb-traefik` name. Flux readiness alone cannot prove the asynchronous K3s
chart operation or external connectivity; complete the gate in
`docs/runbooks/cluster.md`.

The K3s datastore/token backup and application data backup are separate recovery
units. A backup is not accepted until a disposable restore drill succeeds.

## Break Glass

The full suspend, reconcile, and recovery procedure is
`docs/runbooks/flux-break-glass.md`; the summary below is the quick reference.

Normal edits go through Git. The root `flux-system` Kustomization owns the
child Kustomization specs and re-reconciles them every 10 minutes, so an
imperative `flux suspend/resume kustomization <child>` is only a temporary
override while Git disagrees: the parent reverts it on its next interval.

During an incident, suspend the parent root before applying any imperative
child override, and record the exact resource and diff:

```sh
flux suspend kustomization flux-system -n flux-system
flux suspend kustomization apps -n flux-system
```

For a durable suspension, commit the suspension itself to Git
(`spec.suspend: true` on the child) instead of using the imperative
override. Either way, reconcile Git to the desired end state before
resuming the parent, because resuming the root immediately re-applies the
committed child specs:

```sh
git commit  # the desired child state, with any suspension reverted
flux resume kustomization flux-system -n flux-system
flux reconcile source git flux-system -n flux-system
flux reconcile kustomization flux-system -n flux-system --with-source
flux reconcile kustomization apps -n flux-system --with-source
```

Do not use a break-glass apply to create a secret that is not subsequently
recorded as an encrypted SOPS manifest or explicitly classified as ephemeral.
