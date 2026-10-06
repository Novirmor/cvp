# CVP

Infrastructure and GitOps repository for an operator-configured K3s platform
using standard Kubernetes resources.

## I have a host; what next?

**Start with [the node runbook](docs/runbooks/nodes.md).** Every host, the
first and each later one, starts as a freshly installed Debian system and goes
through the same three commands:

```sh
task node-new -- server1 --ssh 203.0.113.20 --virt vm --mesh-address 10.77.0.1 \
  --ssh-key "$HOME/.ssh/cvp-ops" --ssh-source 203.0.113.10/32 --write
task node-bootstrap -- server1 --confirm server1 --host-key-fingerprint SHA256:...
task node-join -- server1 --confirm server1
```

`node-new` writes and validates inventory, host vars, the WireGuard key, and
host-scoped operator settings without touching the host. `node-bootstrap`
checks the host key against the provider-console fingerprint, then copies a
setup script to the fresh host over SSH and runs it as root to create the `ops`
operator. `node-join` probes, joins, and verifies, resuming safely after a
failure. The runbook then exports a TLS-verified kubeconfig over Tailscale.

**Network rules:** the public IP carries SSH (from your listed addresses only),
Cloudflare-proxied HTTP(S) to the ingress node, and the encrypted WireGuard
transport. WireGuard (`wg0`) carries node-to-node cluster traffic only.
Tailscale carries people (and CI) to internal services: the Kubernetes API and
internal applications. Neither WireGuard nor Tailscale carries SSH.

Recommended baseline: Debian 13/systemd/amd64 VM. LXC requires provider-supplied
kernel/cgroup/TUN facilities and a passing compatibility probe. This baseline
matches repository dependencies; it is not a claim of live deployment testing.

| Where you are | Next procedure |
| --- | --- |
| One new host, no cluster | [First host](docs/runbooks/nodes.md#3-first-host) |
| Ready cluster, one more host | [Add another host](docs/runbooks/nodes.md#4-add-another-host), one node at a time |
| Ready API and private kubeconfig | [Cluster/Flux bootstrap](docs/runbooks/cluster.md#bootstrap) |
| Public DNS or tailnet policy adoption | [External providers](docs/runbooks/tofu.md) |
| Production data or recovery | [Backup enablement](ansible/README.md#backup-enablement) and [disposable restore drill](ansible/README.md#datastore-restore) |

The default inventory contains **no hosts** and provisions none. Both
`k3s_cluster_init_host` and `k3s_server_host` default to empty; `task node-new`
selects the first node for both in `ansible/inventory/hosts.yml`'s `all.vars` so
later nodes inherit the same selections. Examples use a replaceable RFC1918 mesh `/24`; choose an
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
task node-new            # scaffold one node's inventory, key, and operator entry (dry run)
task node-join           # trust, access, probe, join, verify one node; resumable
task node-bootstrap      # copy and run the setup script on a fresh Debian host
task validate-inventory   # controller-only, read-only topology validation
task prepare-access      # one new host: trusted root SSH -> ops key and sudo
task probe               # read-only compatibility check before convergence
task site -- --check --diff
task site                # full-fleet convergence
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
literal strings, `{file: PATH}` (a private `0600` file outside the checkout), or
`{env: NAME}`; **every configured reference must resolve on
every loader invocation**, including probes/verification. See
[the host layer guide](ansible/README.md) for the schema, authoritative SSH-key
management, storage approvals, backups, and recovery details.

SSH is public-only: each host's firewall accepts TCP `22` on its public uplinks
from the host-scoped `/32` or `/128` sources in the operator file, and nowhere
else. Firewall preflight refuses to activate unless the current SSH client
matches one of them, and rejects sources overlapping Tailscale or the mesh. See
[changing your SSH address](docs/runbooks/nodes.md#your-public-ssh-address-changed).

Ansible convergence does not bootstrap Flux. Before the separate cluster step,
replace `example.invalid/repository.git` in `cluster/flux-system/source.yaml`
and supply the reviewed repository, deploy key, SOPS identity, and explicit
context as described in [the cluster runbook](docs/runbooks/cluster.md).
