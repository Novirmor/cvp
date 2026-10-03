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

`task test` additionally runs the conftest policy suite in `tests/policy/`
against every rendered overlay: prohibited host networking, hostPath volumes,
privileged and non-restricted security contexts, mutable image tags, and
unbounded resources are rejected before merge, and a deliberately
non-compliant fixture proves each rule fires.

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
   values below with the operator's repository.
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
bootstrap. Instead, bootstrap relies on each child Kustomization's own wait,
and the root health checks still gate the six Flux controller Deployments
before the root reports healthy.

## Post-Bootstrap Traefik Verification

After the `infrastructure` Kustomization first becomes healthy, the ingress
path must still be verified by hand. The Flux health checks on the traefik
Deployment and the svclb-traefik DaemonSet mitigate, but do not prove, the
chart upgrade: K3s applies the `HelmChartConfig` through its own
helm-controller asynchronously from Flux reconciliation, so a health-check
pass can predate the latest Traefik values. Work through this gate:

1. Confirm the K3s helm-controller actually processed the HelmChartConfig:

   ```sh
   kubectl -n kube-system get helmchart traefik -o yaml
   ```

   The rendered values must include the committed configuration and the
   status must show no failed operation.

2. Confirm the traefik Deployment completed its rollout:

   ```sh
   kubectl -n kube-system rollout status deploy/traefik
   ```

3. Confirm the svclb-traefik DaemonSet has a ready pod on the node labeled
   `cvp.io/ingress=true`, so the ServiceLB endpoint is local to the ingress
   node:

   ```sh
   kubectl -n kube-system get ds svclb-traefik -o wide
   kubectl -n kube-system get pods -o wide
   ```

4. From an external vantage point, send an HTTP request to the ingress node
   on port 80 and confirm the redirect targets HTTPS on the public port 443,
   never Traefik's internal port 8443:

   ```sh
   curl -sI http://<ingress-node>/ | grep -i '^location:'
   ```

   The redirect is configured through the chart's structured
   `ports.web.redirectTo` values because the raw entrypoint arguments resolve
   `websecure` to Traefik's internal 8443 and produce broken public
   redirects.

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
