# K3s Cluster Runbook

This runbook covers the cluster resources in `cluster/`. Host installation,
WireGuard, K3s datastore backups, and external DNS remain owned by their
respective layers.

## Safe Validation

Render manifests without contacting a cluster:

```sh
kubectl kustomize cluster
kubectl kustomize cluster/infrastructure/policy/overlays/cluster
kubectl kustomize cluster/infrastructure/ingress/overlays/k3s
kubectl kustomize cluster/apps/overlays/smoke
kubectl kustomize cluster/operations/overlays/cluster
```

Flux v2.5.1 components and CRDs are committed in
`cluster/flux-system/gotk-components.yaml`; the K3s `HelmChartConfig` CRD is a
cluster prerequisite supplied by K3s.

`task test` runs `scripts/test-manifests`. It checks source Secret/generator
structure, follows repository-local Flux paths including suspended children,
and evaluates every discovered render before producing a sanitized
schema-only stream for encrypted Secrets. The policy suite covers native
pod-bearing kinds, effective container security overrides, dropped capabilities,
host ports, immutable images, and positive resource quantities. Only the exact
pinned vendored Flux controller containers receive image/ephemeral-storage
exceptions; new workloads in `flux-system` do not.

Nullable optional maps and arrays are normalized before policy evaluation;
malformed structures fail closed. The rendered null regressions also run through
strict Kubernetes 1.35 schemas, proving that policy rejects inputs schemas permit.
Cross-render checks require explicit workload namespaces and managed restricted
PSA, default-deny, quota, and LimitRange relationships. System exceptions are
limited to the known Flux resources and the K3s Traefik HelmChartConfig.
Build file references must stay inside `cluster/`. Flux-side rendering overrides
and remote kubeconfigs are rejected; express supported transformations in the
local Kustomize overlay so validation sees the same output.

Focused credential-free checks can also run individually:

```sh
python3 scripts/test-cluster-policy
python3 scripts/test-cluster-guards
python3 scripts/test-cluster-traefik
python3 scripts/test-cluster-manifests
python3 scripts/test-cluster-bootstrap
bash scripts/test-manifests
```

The first two checks are offline; they use conftest, Git, SOPS, age, and Python's
standard library. The SOPS test creates its own temporary identity. The chart
test uses Helm to render the exact archive shipped by the pinned K3s version,
checks its committed SHA-256 in
`cluster/infrastructure/ingress/packaged-chart.json`, and asserts redirect and
ServiceLB behavior. Review that pin together with K3s upgrades. For offline
chart testing, set `CVP_CLUSTER_ASSET_DIR` to a directory containing the pinned
chart archive, `k3s-<version>-traefik.yaml`, and `k3s-<version>-servicelb.go`
from that K3s release. The full manifest check and bootstrap orchestration tests
also download Kubernetes schemas. Bootstrap orchestration uses local Git remotes
through an SSH stub and a kubectl stub; it never contacts Kubernetes.

## Bootstrap

1. Complete initial host bootstrap from the empty default inventory as described
   in `ansible-host-bootstrap.md`. The operator explicitly selects the initial
   server; `task onboard` is only for subsequent nodes. Verify that the K3s API,
   CoreDNS, packaged Traefik, and ServiceLB are available.
2. Verify that only the intended ingress node has both
   `svccontroller.k3s.cattle.io/enablelb=true` and
   `svccontroller.k3s.cattle.io/lbpool=public`. It must also have
   `cvp.io/ingress=true` for Traefik.
3. Replace the `example.invalid/repository.git` placeholder in
   `cluster/flux-system/source.yaml` with the reviewed repository URL and branch.
   Set both `FLUX_GITHUB_OWNER` and `FLUX_GITHUB_REPOSITORY` explicitly to match
   the URL (`ssh://git@github.com/<owner>/<repository>.git`); replace the example
   values below with the operator's repository. Commit and push the complete
   `cluster/` tree to that branch first. The helper fetches the remote branch
    through strict SSH host verification and compares its cluster tree and actual
    local file bytes before any Kubernetes command. It fails for local edits,
    untracked cluster files, unpublished configuration, and differences concealed
    by `assume-unchanged` or `skip-worktree`. It validates the fetched snapshot's
    source URL/branch, policies, namespace relationships and strict schemas, then
    applies only that snapshot's bootstrap manifests. The snapshot is deleted on
    exit; deploy and age keys remain separate operator inputs.
   Every Git invocation discards inherited `GIT_*` overrides, and the preflight
    verifies the worktree root is the expected checkout. Bootstrap rejects
    `.sourceignore`, source filters/includes/submodules, cluster symlinks, and
    transforms that make directly applied bootstrap files differ from their
    validated render. Repository-local Flux paths must stay inside `cluster/`.
4. Recover the Git deploy key and SOPS age identity from an operator-chosen
   external secrets store and seed them through the context-safe bootstrap
   helper; Ansible does not own either private key:

   ```sh
   FLUX_GITHUB_OWNER=example-owner \
   FLUX_GITHUB_REPOSITORY=example-repository \
   FLUX_KUBE_CONTEXT=reviewed-cluster-context \
   FLUX_GIT_SSH_KEY_FILE=/path/to/deploy-key \
   FLUX_GIT_KNOWN_HOSTS_FILE=/path/to/known-hosts \
   SOPS_AGE_KEY_FILE=/path/to/recovered/age.key \
     task bootstrap-flux
   ```

The first successful reconciliation creates restricted namespaces, quotas,
limit ranges, default-deny policies, DNS egress rules, and the Traefik config.
The data and apps Flux Kustomizations are intentionally suspended. Operations
CronJobs are also suspended and contain fail-closed templates only.

The root `flux-system` Kustomization reconciles with `wait: false`. The root
does not wait on its children, because the suspended `apps` and `data`
Kustomizations never reconcile and would leave the root unhealthy on a fresh
bootstrap. Each child has its own wait or explicit health checks, and the root
health checks gate the six Flux controller Deployments before the root reports
healthy.

Bootstrap success additionally requires the source artifact and every active
Kustomization's applied revision to equal the verified commit, current-generation
Ready status, and no suspension. Source and root explicitly declare `suspend:
false`, so bootstrap resumes them after break glass. Every child declares its
suspension state; the root restores those states from Git without waiting for
suspended children. The source continues tracking its branch after bootstrap.
The gate runs before and after ingress checks.
Keep the published branch unchanged throughout bootstrap: branch movement fails
the checks, but the helper neither locks Git nor rolls back completed applies.
Old Ready conditions alone are insufficient evidence of recovery.

## Post-Bootstrap Traefik Verification

The `infrastructure` Kustomization uses `wait: false` with an explicit Traefik
Deployment health check. K3s processes HelmChartConfig asynchronously, and the
ServiceLB DaemonSet name contains a Service-UID suffix. Flux Ready alone is not
proof that the new chart values or public traffic path are working.

1. The bootstrap helper runs this read-only check automatically. Repeat it
   after every chart/ingress change and during relocation or recovery:

    ```sh
    python3 scripts/cluster-ingress-ready --context reviewed-cluster-context --timeout 5m
    ```

    It checks the live HelmChartConfig, latest deployed release's chart version
    and intended values, a completed chart Job owned by the current HelmChart,
    the Deployment's observed generation and completed rollout, Service ports,
    placement labels, and ServiceLB pods plus Ready local Traefik endpoints.
    Its timeout fails closed; it does not mutate resources or test the public
    dataplane. The intended values check is a subset comparison, not an audit
    of every default or stale value in the Helm release.

    Helm status does not include chart metadata. The helper fetches metadata
    and values with `helm get ... --revision` bound to the status revision,
    then rechecks the latest status and retries if the release changes during
    collection.

    Inspect the generated DaemonSet by labels when diagnosing a failed gate:

    ```sh
    kubectl -n kube-system get ds -l svccontroller.k3s.cattle.io/svcname=traefik,svccontroller.k3s.cattle.io/svcnamespace=kube-system -o wide
    kubectl -n kube-system get helmchart traefik -o yaml
    ```

    Keep `allocateLoadBalancerNodePorts: true` with `externalTrafficPolicy:
    Local`: the pinned K3s ServiceLB forwards to those NodePorts. Disabling
    them breaks this path; they are not unused allocations. Changing to a
    NodePort-free frontend requires a separate traffic/source-IP design review.

2. From an external vantage point, send an HTTP request to the ingress node
   on port 80 and confirm the redirect targets HTTPS on the public port 443,
   never Traefik's internal port 8443:

   ```sh
   curl -sI http://<ingress-node>/ | grep -i '^location:'
   ```

   The redirect is configured through the chart's structured
   `ports.web.http.redirections.entryPoint` values because raw entrypoint arguments resolve
   `websecure` to Traefik's internal 8443 and produce broken public
   redirects. The packaged chart silently ignores the obsolete `redirectTo`
   key; the local render test detects the missing redirect arguments.

Bootstrap is not complete until this manual gate passes.

## Enablement Gates

Before enabling the smoke app, replace its placeholder hostname and provide the
required certificate path. A production app must use a reviewed immutable image
digest, explicit resources and probes, an app-specific policy, and a tested
rollback.

Before enabling backups, select the application-native dump, object-store
endpoint, retention, encryption, and restore procedure. Add only the required
egress rule, create `backup-credentials` as an encrypted SOPS Secret, replace
the template image with a reviewed digest, and run a disposable restore drill.

## Recovery

Restore the K3s datastore and matching server token together when using the
existing control-plane state. For a clean cluster, install K3s, restore the two
out-of-band secrets through `task bootstrap-flux` with explicit
`FLUX_GITHUB_OWNER`, `FLUX_GITHUB_REPOSITORY`, and context inputs,
and wait for policy and ingress before restoring stateful data. Verify both
ServiceLB labels on the recovered ingress node before enabling the public route.
Restore local-path data separately, then enable the approved data and app layers.
