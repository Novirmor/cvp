# __NAME__

This repository runs one K3s platform built on [CVP](__PLATFORM_URL__). It holds
only what is specific to this platform; everything reusable comes from the
pinned `platform/` submodule.

| Path | Owner | Contents |
| --- | --- | --- |
| `platform/` | CVP (pinned) | Ansible roles, guarded scripts, cluster policy/ingress/operations layers, OpenTofu roots, runbooks |
| `inventory/` | you | Hosts (`hosts.yml`, `host_vars/`), overrides of platform defaults (`group_vars/all.yml`) |
| `cluster/flux-system/` | you | Flux entry point: this repository's source, the pinned platform source, the reconciliation graph |
| `cluster/apps/` | you | Your applications (Flux reconciles them from this repository) |
| `Taskfile.yml` | you | Includes every platform task; adds `validate` and `platform-upgrade` |

Secrets never enter this repository in plain text: host credentials live in the
per-user operator file (`~/.config/cvp/__NAME__/operator.yml`, mode `0600`),
and cluster secrets are SOPS-encrypted (`cluster/.sops.yaml.example`).

## Quickstart

```sh
git clone --recurse-submodules <this repository>
cd __NAME__
mise install
task validate
task init          # take a fresh Debian host to a cluster node; rerun for more hosts
```

`task init` asks for the host's public IP, the SSH fingerprint from the
provider console, and a Tailscale auth key, then bootstraps, joins, and exports
a kubeconfig. Network rules, the manual steps, and troubleshooting are in
[the node runbook](platform/docs/runbooks/nodes.md).

Before bootstrapping Flux, set `cluster/flux-system/source.yaml` to this
repository's SSH URL, then follow
[the cluster runbook](platform/docs/runbooks/cluster.md#bootstrap). Flux pulls
the platform layers from the commit pinned in
`cluster/flux-system/platform-source.yaml`, the same commit as `platform/`.

## Upgrading the platform

```sh
task platform-upgrade -- v0.2.0   # tag, branch, or commit
git diff                          # review, and read platform/CHANGELOG.md
mise install && task validate
git commit -am "chore: platform v0.2.0" && git push
```

Flux applies the new platform layers after the push; run `task site` to apply
host-layer changes.
