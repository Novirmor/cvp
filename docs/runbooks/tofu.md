# OpenTofu External Providers

The two roots under `tofu/` have separate state boundaries:

- `tofu/cloudflare` owns explicitly declared public Cloudflare DNS records.
- `tofu/tailscale` owns the complete Tailscale ACL policy and DNS configuration.

Neither root creates Kubernetes resources or configures hosts. K3s cluster
networking, WireGuard ports, host firewall rules, and Tailscale installation
remain owned by the other repository layers described in `ARCHITECTURE.md`.

## Credentials

Provide credentials through the environment or an external secret manager. Do
not put them in `*.tfvars`, backend files, shell history, or this repository.

- Cloudflare: `CLOUDFLARE_API_TOKEN`, scoped to the required zone with DNS Read
  and DNS Write permissions.
- Tailscale: `TAILSCALE_API_KEY`, or the provider's OAuth environment variables
  with permissions to manage the tailnet policy and DNS configuration.
- S3 backend: use the backend's standard environment or workload credentials.

## First Use

Run each root independently. Do not initialize one root from the other root's
directory or reuse its backend key. The committed dependency locks require
OpenTofu 1.12 or later (and before 2.0).

```sh
task cloudflare-init -- -backend-config=/path/outside/repository/cloudflare-backend.hcl
# Prepare the variables file outside the repository:
#   cp tofu/cloudflare/examples/terraform.tfvars.example \
#      /path/outside/repository/cloudflare.tfvars
# Replace the zone and documentation addresses in the copied variables file.
mise exec -- tofu fmt -check tofu/cloudflare
task test
task cloudflare-plan -- \
  -var-file=/path/outside/repository/cloudflare.tfvars \
  -out=/path/outside/repository/plans/cloudflare-YYYYMMDD.tfplan
task cloudflare-show -- \
  /path/outside/repository/plans/cloudflare-YYYYMMDD.tfplan
```

Repeat for Tailscale with `task tailscale-init`, `task tailscale-plan`, and its
own backend file, state key, and variable file. The example identity values
are placeholders and must be replaced with real Tailscale identities.
`records` is deliberately required to contain at least one Cloudflare record:
omitting the variable file or passing `{}` fails validation instead of
producing a delete-all plan.

Replace documentation-only addresses with the operator-selected ingress node's
public addresses. Enable the example A record only if that node has a public
IPv4 address; include an AAAA record only if it has public IPv6. Review every
declared address family before planning.

Review the saved plan before applying. Apply that exact reviewed artifact; do
not run a second plan+apply, which creates and applies a new plan instead.

```sh
task cloudflare-apply -- /path/outside/repository/plans/cloudflare-YYYYMMDD.tfplan
```

The tasks require saved plan paths to be absolute and outside the repository;
plan files can reveal resource configuration. Use `task cloudflare-drift-plan`
or `task tailscale-drift-plan` with an external `-out` path when inspecting
drift without changing provider resources, and review that artifact in the same
way.

## Deletion Safeguards

All Cloudflare records, the Tailscale ACL, and the Tailscale DNS configuration
use `lifecycle.prevent_destroy`. The guard exists only while the resource block
remains in configuration:

- Removing a map key (or otherwise shrinking a keyed resource) while the
  guarded block stays in configuration fails instead of deleting the live
  object. Running `tofu destroy` while the guarded blocks remain also fails.
  This is intentional.
- Removing the whole resource block removes the guard with it: OpenTofu then
  plans to destroy the object without the `prevent_destroy` check. Do not rely
  on the guard surviving deletion of its resource block.

To deliberately relinquish management without deleting the remote object on
OpenTofu 1.12 or later, adopt `lifecycle { destroy = false }` on the resource
before removing its block, so the object stays in the state and in the remote
provider. Alternatively, use a reviewed `removed` block workflow when handing
the address to another root (see State Handoff).

To retire a managed object for real deletion, first approve a plan that
identifies the exact deletion and its impact. Temporarily remove the relevant
`prevent_destroy` guard in a reviewed change, produce and apply one saved plan
artifact, then remove the object from configuration. Do not leave a resource
unguarded after an unrelated change.

## Adopting External Resources

When adopting external resources, inventory and import them before the first
managed apply. Cloudflare's v5 DNS resource has no overwrite escape hatch, so a
duplicate create fails. The Tailscale ACL intentionally sets
`overwrite_existing_content = false`.

The Tailscale ACL resource manages the *entire* tailnet policy, not just the
groups, tags, ACLs, and tests declared in this root. Importing it then applying
this configuration removes every existing policy field that is not represented
by `local.policy`, including grants, SSH rules, device posture rules, auto
approvers, tests, tag owners, and hosts. Inventory and explicitly represent every
required policy feature before the first apply. Do not use this root until the
tailnet owner has approved the complete replacement policy and a rollback
policy snapshot is available.

Cloudflare record import uses the zone and record IDs:

```sh
task cloudflare-import -- \
  'cloudflare_dns_record.public["ingress_a"]' ZONE_ID/RECORD_ID
```

Tailscale policy and DNS imports use the provider resource IDs:

```sh
task tailscale-import -- tailscale_acl.policy acl
task tailscale-import -- tailscale_dns_configuration.tailnet dns_configuration
```

Inspect the resulting plan after each import. Do not use `-target` as a normal
deployment method, and do not enable overwrite flags to bypass an inventory.

### State Handoff

If transferring ownership between roots, freeze the source Terraform/OpenTofu
automation before the handoff: disable its
scheduled and CI applies, revoke or pause any other apply path, and keep it
frozen until the new root has applied cleanly and the old state no longer owns
the resources. Two active states must never manage the same external object.

For a complete root whose backend location alone is changing, initialize from
that same root with the new backend configuration and let OpenTofu copy the
whole state:

```sh
tofu init -migrate-state -backend-config=/path/outside/repository/new-backend.hcl
tofu state pull > /path/outside/repository/state-backups/root-after-migration.tfstate
```

Do not use `-migrate-state` to split a shared old state into these two roots.
For a split, make local state artifacts while the old automation is frozen,
move each address into the destination artifact, then push the destination and
remove the source ownership. Initialize both the old root and the destination
root against their real backends before these commands.

```sh
# Snapshot both remote states before changing either one.
tofu -chdir=/path/to/old/root state pull \
  > /path/outside/repository/state-backups/old-before-handoff.tfstate
tofu -chdir=tofu/cloudflare state pull \
  > /path/outside/repository/state-backups/cloudflare-before-handoff.tfstate

# Preserve immutable snapshots; state mv rewrites its input and output artifacts.
cp /path/outside/repository/state-backups/old-before-handoff.tfstate \
  /path/outside/repository/state-backups/old-working.tfstate
cp /path/outside/repository/state-backups/cloudflare-before-handoff.tfstate \
  /path/outside/repository/state-backups/cloudflare-working.tfstate

# Move one address between local working artifacts. Repeat for every record.
tofu state mv \
  -state=/path/outside/repository/state-backups/old-working.tfstate \
  -state-out=/path/outside/repository/state-backups/cloudflare-working.tfstate \
  'module.external.cloudflare_dns_record.public["ingress_a"]' \
  'cloudflare_dns_record.public["ingress_a"]'

# Upload destination ownership, then remove only that address from the old backend.
tofu -chdir=tofu/cloudflare state push \
  /path/outside/repository/state-backups/cloudflare-working.tfstate
tofu -chdir=/path/to/old/root state rm \
  'module.external.cloudflare_dns_record.public["ingress_a"]'
```

Use the actual old address shown by `tofu state list`; do not copy the example
module path blindly. Run `tofu state list` in both roots after each move.

Transferring state ownership alone is not complete: the old root still declares
the transferred objects, so resuming its automation would recreate them (for
example, a second DNS record with different content). While the old automation
stays frozen, remove or retire the transferred declarations from the old root.
Then produce and review saved plans from BOTH roots before unfreezing either
automation: the old root's plan must show no create or destroy of the
transferred objects, and the new root's plan must show the intended ownership.

Import is the safer alternative when the old state cannot be edited: import into
the new root, verify its saved plan, then remove the old state address while
applies remain frozen.

## Policy Surface

The Tailscale policy is deny-by-default and only permits TCP paths needed by
the K3s layout:

- `group:admin` to `tag:k3s`: SSH `22` and Kubernetes API `6443`.
- `group:admin` to `tag:k3s-ingress`: ingress/API testing on `80`, `443`.
- `group:ci` and `tag:ci` to `tag:k3s`: Kubernetes API `6443` only.

Nodes need the `tag:k3s` tag. The operator-selected ingress node also needs
`tag:k3s-ingress`, and an ephemeral CI device must use `tag:ci`. Only the admin
group owns these tags. The policy does not grant Tailscale access to Flannel
VXLAN `8472` or kubelet `10250`; those are internal WireGuard-scoped ports, not
operator or CI access paths.

Cloudflare records should point only at the selected public ingress node. Keep
records explicit, avoid broad wildcard ownership, and update both address
families as part of the reviewed ingress relocation
(see `ingress-relocation.md`).

## DNS Safety

`tailscale_dns_configuration` manages MagicDNS, global nameservers, search
paths, and split DNS as one object. It must not be combined with the provider's
individual DNS resources. Split-DNS nameservers must be reachable by Tailscale
clients; Kubernetes service discovery remains CoreDNS inside the cluster and
should not be represented by a guessed ClusterIP here.

The backend examples are placeholders only. No backend state, credentials, or
generated plan belongs in Git. The generated `.terraform.lock.hcl` files are
provider selections and should remain committed for reproducible initialization.

The repository's root `.gitignore` covers HCL and JSON variable files
(`*.tfvars`, `*.tfvars.json`, `*.auto.tfvars.json`) and backend files
(`*.tfbackend`, `*.tfbackend.json`, `backend.hcl`, `*.backend.*`). Keep any
other state-bearing artifacts outside the repository; this runbook does not
modify root-level ignore rules.
