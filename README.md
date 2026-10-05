# CVP

Infrastructure and GitOps repository for an operator-configured K3s platform
using standard Kubernetes resources.

## I have a host; what next?

**Start with [the first-host runbook](docs/runbooks/ansible-host-bootstrap.md).**
It takes one existing host through controller setup, trusted SSH, a complete
`server1` inventory, host-scoped secrets, compatibility checks, K3s convergence,
private SSH migration, and a TLS-verified private kubeconfig.

Recommended baseline: Debian 13/systemd/amd64 VM. LXC requires provider-supplied
kernel/cgroup/TUN facilities and a passing compatibility probe. This baseline
matches repository dependencies; it is not a claim of live deployment testing.

| Where you are | Next procedure |
| --- | --- |
| One new host, no cluster | [First-host bootstrap](docs/runbooks/ansible-host-bootstrap.md): use `task site` |
| Ready cluster, one more host | [Node onboarding](docs/runbooks/node-onboarding.md): use `task onboard`, one node at a time |
| Ready API and private kubeconfig | [Cluster/Flux bootstrap](docs/runbooks/cluster.md#bootstrap) |
| Public DNS or tailnet policy adoption | [External providers](docs/runbooks/tofu.md) |
| Production data or recovery | [Backup enablement](ansible/README.md#backup-enablement) and [disposable restore drill](ansible/README.md#datastore-restore) |

The default inventory contains **no hosts** and provisions none. Both
`k3s_cluster_init_host` and `k3s_server_host` default to empty; explicitly select
them in inventory before bootstrap. The first-host example places both on
`server1` in `ansible/inventory/hosts.yml`'s `all.vars` so future nodes inherit
the same selections. Examples use a replaceable RFC1918 mesh `/24`; choose an
unused subnet, not a documentation-only address range. Public example IPs and
all credential/identity placeholders must be replaced.

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

## Repository layout

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

Run from the repository root with mise activated for your shell (or use
`mise exec -- task …`):

```sh
mise install
task deps
task lint
task test
task security
```

Development checks run without infrastructure credentials; tool/dependency,
schema, chart, and provider downloads mean **credential-free is not offline**.
Operational tasks can change live hosts, clusters, and provider resources after
configuration.

Use the pinned `mise.toml` toolchain, including uv and Ansible with `jsonpatch`.
Existing Ansible installations may need `mise install --force pipx:ansible-core`
to pick up the added Python dependencies. Controller prerequisites include Git,
Python/PyYAML, `sqlite3`, and OpenSSH client/server tools. Local tests need
`ssh-keygen` and a real OpenSSH `sshd` parser on `PATH` or selected through
`CVP_TEST_SSHD` (for example `/usr/sbin/sshd`); the parser test does not start a
daemon. Install `wireguard-tools` for onboarding key generation. The first-host
runbook includes a Debian controller package command.

Linux kernel integration checks run separately, without sudo/root, in disposable
unprivileged user/network namespaces:

- `task test-firewall-dataplane` requires `unshare`, `nsenter`, `ip`, `nft`, and
  `sysctl`, with veth, IPv6, nftables, and conntrack/NAT kernel support. It tests
  the rendered firewall with real IPv4/IPv6 traffic and DNAT.
- `task test-wireguard-dataplane` requires `unshare`, `ip`, `wg`, `wg-quick`, and
  kernel WireGuard support. It tests in-place reconciliation, drift, key rotation,
  and endpoint roaming while preserving interface identity.

Missing tools or namespace/kernel support fail these checks. Repository and
isolated kernel test passes are not evidence of production multi-node K3s,
WireGuard path/MTU, reboot, or off-host recovery drills.

## Operations quick reference

Use the runbooks for inputs, sequencing, expected results, and failure handling.
`task --list` shows the complete Taskfile surface. These are reference commands,
not a bootstrap script to run without configuration:

```sh
task validate-inventory   # controller-only, read-only topology validation
task prepare-access      # one new host: trusted root SSH -> ops key and sudo
task probe               # read-only compatibility check before convergence
task site -- --check --diff
task site                # first host / later full-fleet convergence
task onboard             # one subsequent node; guarded full-fleet convergence
task probe-wireguard     # read-only mesh/path MTU check after convergence
task verify              # read-only host, network, storage, and API checks
task export-kubeconfig   # explicit host/context/private TLS endpoint; external output
task restore-k3s         # destructive recovery; follow the host-layer guide
task bootstrap-flux      # separate cluster bootstrap with an explicit context
task cloudflare-plan     # provider roots have separate init/plan/show/apply tasks
task tailscale-plan
```

Arguments pass through after `--`. Site validates the whole topology even
under `--limit`: explicit roles, one init server, **exactly one ingress node**,
unique WireGuard public keys/addresses in one `/24`, and consistent shared
settings. Storage-enabled mountpoints must equal the shared
`k3s_default_local_storage_path` (default `/var/lib/rancher/k3s/storage`).
Mutating selections must include both the init and designated API/token server
to lock shared dependencies. Failed site operations can retain
`/var/lib/cvp/lifecycle.lock`; inspect ownership and interrupted state before
explicit cleanup. Locks are never stolen automatically.

Keep persistent operator settings outside Git in
`$XDG_CONFIG_HOME/cvp/operator.yml` (default `~/.config/cvp/operator.yml`), or
select an absolute external path with `CVP_OPERATOR_CONFIG_FILE`. Credentials
and destructive approvals are host-scoped. Supported credential fields accept
literal strings or `{env: NAME}`; **every configured reference must resolve on
every loader invocation**, including probes/verification. See
[the host layer guide](ansible/README.md) for the schema, authoritative SSH-key
management, storage approvals, backups, and recovery details.

Ordinary unbound sshd sessions require an explicit host-scoped SSH source CIDR
matching the client address seen by the host, including the client's Tailscale
`/32` or `/128` after migrating to private SSH. Tailscale `Running` and a private
login do not permit clearing that allowance: CIDR-less firewall preflight requires
kernel interface-bound socket evidence and a matching return route. Follow the
[private SSH migration procedure](docs/runbooks/ansible-host-bootstrap.md#7-move-ssh-to-the-private-address-before-closing-public-ssh).

Ansible convergence does not bootstrap Flux. Before the separate cluster step,
replace `example.invalid/repository.git` in `cluster/flux-system/source.yaml`
and supply the reviewed repository, deploy key, SOPS identity, and explicit
context as described in [the cluster runbook](docs/runbooks/cluster.md).
