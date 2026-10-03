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
flux suspend kustomization policy infrastructure operations -n flux-system
flux suspend source git flux-system -n flux-system
```

Suspending the source stops new revision fetches; the children keep their
last applied revision. Verify with `flux get kustomizations -n flux-system`
and `flux get sources git -n flux-system` (the Suspended column must agree
with the incident decision). `data` and `apps` are already suspended in Git
and are not part of an emergency suspension.

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
flux reconcile kustomization policy infrastructure operations -n flux-system --with-source
```

If the source fetched a bad revision that Git has since fixed, the forced
`--with-source` reconcile is what discards it; the kustomize-controller never
applies an artifact that is not the source's current revision.

## Controller failure

Controllers are ordinary Deployments in `flux-system`:

```sh
kubectl -n flux-system get deploy
kubectl -n flux-system get events --sort-by=.lastTimestamp
kubectl -n flux-system rollout restart deploy/<controller>
```

If the namespace or the CRDs are damaged, re-run the bootstrap helper against
an explicit context with the recovered deploy key and SOPS age identity (see
`cluster.md`); it reinstalls the committed components and waits for the
policy, infrastructure, and operations Kustomizations to become Ready:

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
URL and verify its branch.

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
