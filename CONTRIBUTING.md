# Contributing

## Rules

- Keep host configuration in Ansible and in-cluster resources under Flux.
- Do not invoke application deployment from Ansible.
- Do not commit plaintext credentials, private keys, kubeconfigs, state, plans,
  age identities, or rendered Secret values.
- Pin production images by digest.
- Prefer native Kubernetes resources and maintained upstream charts over local
  abstractions.
- Add a controller or operator only when its recovery and maintenance cost is
  lower than the mechanism it replaces.
- Every persistent service change includes backup and restore impact.
- Every public exposure change includes DNS, TLS, firewall, and rollback impact.

## Checks

```sh
task lint
task test
task security
```

Live changes require an inspected diff or plan. Destructive live changes also
require a verified backup or explicit accepted-loss decision for affected data,
and the relevant recovery gate from `PLAN.md`.
