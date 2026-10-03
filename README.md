# CVP

Infrastructure and GitOps repository for an operator-configured K3s platform
using standard Kubernetes resources.

## Status

The repository starts without configured hosts or provider deployment inputs.
Development checks run without infrastructure credentials; operational tasks can
change live hosts, clusters, and provider resources after explicit configuration.

No hosts are provisioned in the default inventory. Both
`k3s_cluster_init_host` and `k3s_server_host` default to empty; the operator must
populate inventory and explicitly select the initial server before bootstrap.
Documentation examples use `server1` and the synthetic `192.0.2.0/24` mesh;
replace these with operator-chosen names and addresses before use.

## Operating model

- Ansible owns the host: operating system, access, firewall, Tailscale,
  WireGuard, disks, and K3s installation.
- An operator-configured WireGuard mesh is the private node-to-node underlay.
- K3s owns cluster networking, service discovery, ingress, workloads, storage
  declarations, and application lifecycle.
- Flux reconciles in-cluster desired state from Git.
- OpenTofu owns only external Cloudflare and Tailscale policy resources.
- An operator-chosen external secrets store holds credentials and recovery keys.
- Recovery, not uninterrupted high availability, is the availability model.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [PLAN.md](PLAN.md).

## Planned layout

```text
ansible/                 Host and K3s bootstrap
cluster/                 Flux-managed Kubernetes desired state
  flux-system/           Flux bootstrap and reconciliation graph
  infrastructure/        Cluster-wide controllers and policy
  apps/                  Application workloads
tofu/                    External Cloudflare and Tailscale resources
tests/                   Policy tests for rendered cluster manifests
docs/                    Runbooks and durable decisions
```

## Development

```sh
mise install
task deps
task lint
task test
task security
```

## Operations

Every operation — host bootstrap, convergence, verification, recovery, Flux
bootstrap, and OpenTofu plan/apply — runs through the repository `Taskfile`.
Run `task --list` for the full surface with usage examples. The main entry
points:

```sh
task probe               # read-only host compatibility probe before convergence
task probe-wireguard     # read-only mesh and path MTU probe after convergence
task prepare-access      # first SSH login: install ops key and sudo via root access
task onboard             # add a node to an initialized cluster after inventory/key preparation
task bootstrap-access    # low-level root-to-ops bootstrap; prefer prepare-access
task site                # converge hosts and the K3s cluster
task verify              # read-only health verification
task restore-k3s         # destructive datastore recovery (see ansible/README.md)
task bootstrap-flux      # one-time Flux bootstrap
task cloudflare-plan     # OpenTofu roots: <root>-init/-plan/-apply
task tailscale-plan
```

Arguments pass through after `--`, for example
`task site -- --check --diff`. All mutation tasks assume the corresponding
gates from `PLAN.md` and the runbooks under `docs/runbooks/` have been
reviewed; secret material always arrives through environment variables or
files outside this repository.

Initial host bootstrap follows
[the host bootstrap runbook](docs/runbooks/ansible-host-bootstrap.md).
Use `task onboard` only for subsequent nodes; it does not initialize a control
plane. Before Flux bootstrap, replace the `example.invalid/repository.git`
placeholder in `cluster/flux-system/source.yaml` with the reviewed repository
URL. Set both `FLUX_GITHUB_OWNER` and `FLUX_GITHUB_REPOSITORY` explicitly as
shown in [the cluster runbook](docs/runbooks/cluster.md).
