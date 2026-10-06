# Changelog

All notable changes to this repository are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

First release candidate. Everything below is verified by the credential-free
checks (`task lint`, `task test`, `task security`) and the isolated
network-namespace dataplane tasks. It has **not** been verified by a live
deployment; see the open items and exit gates in `PLAN.md`.

### Added

- **Platform and instance repositories.** This repository is now a reusable
  platform; each operator runs an instance repository created with
  `task new-instance -- ../my-platform --platform-url https://...`:
  - the instance pins the platform as a `platform/` submodule and includes its
    tasks (`tasks/ops.yml`), so `task init`, `node-*`, `site`, `verify`, and the
    provider tasks run against the instance's inventory and cluster;
  - Flux reconciles policy, ingress, operations, and data from a `cvp-platform`
    GitRepository pinned to the submodule commit, and apps from the instance;
    the validator and bootstrap preflight render those layers from that exact
    commit and reject any mismatch;
  - `task validate` and `task platform-upgrade -- <ref>` keep the submodule,
    Flux pin, copied Flux components, and toolchain in step;
  - platform defaults moved to `ansible/defaults/` and load before the instance
    inventory, whose `group_vars/all.yml` overrides them; operator files, keys,
    state, and kubeconfigs are scoped per instance under
    `~/.config/cvp/<instance>/`.
- Licensed under MIT.
- **Guided setup.** `task init` takes a fresh Debian host to a joined node:
  it creates the operator SSH key if needed, verifies the host key against the
  console fingerprint, detects your SSH source from the host's view of the
  connection, bootstraps the host, scaffolds and validates the inventory, joins
  the node, and exports a Tailscale kubeconfig for the first host. It asks only
  for what it cannot detect, shows plans before writing, and is safe to rerun
  to resume or to add the next host.
- **Node workflow.** `task node-new`, `task node-bootstrap`, and
  `task node-join` take every host from a fresh Debian install to a joined
  node, replacing the manual first-host and onboarding procedures:
  - `node-new` allocates the mesh address, generates the WireGuard key
    (`~/.config/cvp/keys/<node>.wg-private`, mode `0600`), and writes host vars,
    inventory groups, and the host-scoped operator entry as one transaction. It
    is a dry run unless `--write`, and rolls back if inventory validation fails.
  - `node-bootstrap` trusts a fresh host's SSH key only when it matches the
    provider-console fingerprint, copies `scripts/node-bootstrap.sh` to the host
    over SSH, and runs it as root (password allowed once; `--login-user` for
    sudo-only cloud images). The script installs Python, sudo, SSH, and probe
    tools and creates the `ops` operator; the command then proves `ops` login
    and sudo.
  - `node-join` handles the first host and every later one: it validates,
    probes, checks fleet membership, converges, probes the mesh, and verifies.
    Progress is recorded, so a rerun resumes after the last completed mutating
    stage. An interrupted `site` requires `--retry-reviewed`. `--preview` stops
    after a check-mode diff.
- **Network rules.** The public IP carries SSH (listed operator sources only),
  Cloudflare-proxied HTTP(S), and the WireGuard transport; WireGuard carries
  node-to-node cluster traffic only; Tailscale carries people and CI to the API
  and internal applications only:
  - the firewall accepts SSH only on public uplinks, never on `tailscale0` or
    `wg0`, and preflight rejects Tailscale or mesh SSH sessions and sources;
  - public `80`/`443` on the ingress node, including forwarded ServiceLB DNAT
    traffic, accept only Cloudflare's published ranges
    (`firewall_public_ingress_ipv4_source_cidrs`/`_ipv6_`);
  - the tailnet policy no longer grants SSH and its tests assert the denial;
    Tailscale SSH is forced off (`--ssh=false`) on every node;
  - K3s servers add their live Tailscale addresses to the API certificate, so
    kubeconfigs reach the API over the tailnet with TLS verification.
- `{file: PATH}` credential references in the operator configuration, for
  private (`0600`, user-owned) files outside the checkout. Referenced files are
  pinned with their own digest (`CVP_OPERATOR_FILES_SHA256`), so replacing one
  mid-run stops the operation.
- Host roles with explicit, verified activation instead of handlers: sshd
  validation, nftables with admin-access checks, WireGuard state reconciliation,
  Tailscale enrollment, IPv6 ingress forwarding, and storage safety inspection.
- K3s lifecycle locks, a start guard, config and NodePort validation,
  identity-bound encrypted datastore backups, and a hardened restore with
  rollback.
- Offline inventory and topology validation (`task validate-inventory`), a
  full-membership onboarding preflight, and private TLS-verified kubeconfig
  export (`task export-kubeconfig`).
- Flux bootstrap preflight and readiness gates, a pinned packaged Traefik
  chart, and secret and structure policy tests.
- Guarded OpenTofu operations in Python with tailnet identity protection.
- CI runs the new suites and real-kernel firewall and WireGuard dataplane
  checks in unprivileged network namespaces.

### Changed

- `docs/runbooks/nodes.md` replaces `ansible-host-bootstrap.md` and
  `node-onboarding.md`. Its reference examples are generated by the documented
  commands, and a test keeps the two in sync.
- `task onboard` is now a compatibility alias for `node-join` on an existing
  cluster. It runs `task validate-inventory` instead of the full `task test`
  suite, which took over 20 minutes on the operator's critical path.

### Removed

- `scripts/test-onboard-node`, superseded by `scripts/test-node-lifecycle.py`.
