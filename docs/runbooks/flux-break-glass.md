# Flux Break-Glass Runbook

Suspend, reconcile, and recover Flux when Git-driven reconciliation is
harmful or broken. Normal operation never uses this runbook: changes arrive
through Git, and the root `flux-system` Kustomization re-applies the committed
child specs every 10 minutes.

The reconciliation graph (see `cluster/flux-system/reconciliation.yaml`):

```text
flux-system (root, owns the source and every child spec)
├── policy          namespaces, PSA, quotas, default-deny
├── infrastructure  Traefik HelmChartConfig (depends on policy)
├── data            suspended, reserved stateful layer (depends on policy)
├── apps            suspended smoke overlay (depends on infrastructure)
└── operations      backup templates (depends on infrastructure)
```

Suspending the root stops the parent from reverting things; it does not stop
the children, because each Kustomization object drives its own reconciliation
loop. A full stop suspends the root, the children, and the source.

## When to break glass

- A merged commit is actively harmful (bad rollout, wrong secrets): suspend,
  revert in Git, reconcile. Prefer `git revert` over manual cluster edits so
  Git remains the record.
- An incident requires imperative cluster changes Flux would revert: suspend
  the root first, mutate, record the diff, then encode the end state in Git
  before resuming.
- Git is unavailable or untrusted (bad revision, source compromise): suspend
  the source and the root, fix Git out of band, resume with a forced refresh.
- Flux controllers are down: see the controller failure section.

## Suspending reconciliation

```sh
flux suspend kustomization flux-system -n flux-system
flux suspend kustomization policy infrastructure data apps operations -n flux-system
flux suspend source git flux-system -n flux-system
```

Record the prior suspension states before the commands. Suspending the source
stops new revision fetches; it does not stop children applying the cached
artifact. Suspending a Kustomization does not cancel an execution already in
progress, so wait for in-flight work to settle before imperative recovery.
Verify with `flux get kustomizations -n flux-system`
and `flux get sources git -n flux-system` (the Suspended column must agree
with the incident decision). Include `data` and `apps` even though they ship
suspended: they may have been enabled since bootstrap. Include any subsequently
added children as well.

An imperative suspension is temporary by design: the committed child specs
are the durable state. A suspension that must survive the incident becomes a
`spec.suspend: true` commit instead.

## Reconciling after a fix

Revert or repair the Git state first, then resume in dependency order and
force each level to reconcile immediately rather than waiting out the
interval:

```sh
flux resume source git flux-system -n flux-system
flux reconcile source git flux-system -n flux-system
flux resume kustomization flux-system -n flux-system
flux reconcile kustomization flux-system -n flux-system --with-source
for child in policy infrastructure operations; do
  flux reconcile kustomization "$child" -n flux-system --with-source || exit 1
done
```

Use the reviewed enabled child set from Git in that loop: add `data` after
`policy` and `apps` after `infrastructure` when enabled, preserving any required
data-before-app dependency. Do not resume a child that is durably suspended in
Git. The root restores the committed child specs, including explicit false
suspension values on the default active children. Reconcile one child per
command; the pinned Flux reconcile CLI processes only its first positional name.

Refresh the repaired source while the Kustomizations are still suspended and
verify its revision before resuming the root. This prevents resuming against a
known stale artifact; it does not retroactively cancel an already-started apply.
After ingress changes, run the explicit-context `cluster-ingress-ready` check
and external HTTP/TLS gate in `cluster.md`.

## Controller failure

Controllers are ordinary Deployments in `flux-system`:

```sh
kubectl -n flux-system get deploy
kubectl -n flux-system get events --sort-by=.lastTimestamp
kubectl -n flux-system rollout restart deploy/<controller>
```

If the namespace or the CRDs are damaged, re-run the bootstrap helper against
an explicit context with the recovered deploy key and SOPS age identity (see
`cluster.md`); it validates and installs an immutable fetched snapshot, then waits
for the source and every active Kustomization to become Ready at that verified
commit and current generation. Keep the branch unchanged until bootstrap finishes:

```sh
FLUX_GITHUB_OWNER=example-owner \
FLUX_GITHUB_REPOSITORY=example-repository \
FLUX_KUBE_CONTEXT=reviewed-cluster-context \
FLUX_GIT_SSH_KEY_FILE=/path/to/deploy-key \
FLUX_GIT_KNOWN_HOSTS_FILE=/path/to/known-hosts \
SOPS_AGE_KEY_FILE=/path/to/recovered/age.key \
  task bootstrap-flux
```

Replace the example owner and repository with the reviewed GitHub values.
Before running the helper, replace the `example.invalid/repository.git`
placeholder in `cluster/flux-system/source.yaml` with the matching repository
URL and verify its branch. Commit and push the complete cluster configuration
to that branch before invoking the helper; its preflight compares actual file
bytes, including edits hidden by Git index flags, before contacting Kubernetes.
Branch-race failures do not roll back already completed applies.

## Resuming safely

1. Confirm Git holds the desired end state and every imperative mutation
   made during the incident is either encoded in a commit or explicitly
   reverted.
2. Resume and reconcile as above, then verify no Kustomization is suspended
   unless Git says so: `flux get kustomizations -n flux-system`.
3. Check every object the incident touched for drift the reconcilers cannot
   see (fields Flux does not own, such as imperatively edited Secrets): a
   break-glass apply may only leave behind objects that a subsequent commit
   or an explicit ephemeral-secret classification accounts for.
4. Record the timeline, the exact suspends, and the manual diffs in the
   incident log; the audit trail is the recovery evidence.

## Boundaries

- Never commit the SOPS age private key, the deploy key, or an unencrypted
  Secret during recovery; recover keys from the operator-chosen external
  secrets store and inject them through `scripts/bootstrap-flux`.
- Do not raise privileges or disable pruning to work around a failed
  reconciliation; fix the manifests or suspend and investigate.
