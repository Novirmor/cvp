# OpenTofu External Providers (Encrypted Local State)

The two roots under `tofu/` have separate state boundaries:

- `tofu/cloudflare` owns explicitly declared public Cloudflare DNS records.
- `tofu/tailscale` owns the complete Tailscale ACL policy, DNS configuration,
  and explicitly requested one-use node enrollment keys.

Neither root creates Kubernetes resources or configures hosts. K3s cluster
networking, WireGuard ports, host firewall rules, and Tailscale installation
remain owned by the other repository layers described in `ARCHITECTURE.md`.

## Credentials

Use SOPS/age-encrypted environment files for provider credentials and each
root's **separate high-entropy** `TF_VAR_state_passphrase`. Keep the age private
key outside Git with an offline recovery copy. A remote secret store is optional;
if later adopted, encrypt its contents as well. Never put secrets in `*.tfvars`,
backend files, arguments, shell history, or unencrypted local state backups.
Prefer a separate operator age identity from the Flux cluster-decryption
identity; the latter must not be required just to recover OpenTofu state.

- Cloudflare: `CLOUDFLARE_API_TOKEN`, scoped to the required zone with DNS Read
  and DNS Write permissions.
- Tailscale: `TAILSCALE_API_KEY`, or the provider's OAuth environment variables
  with permissions to manage the tailnet policy and DNS configuration.

OpenTofu uses PBKDF2 and AES-GCM with `enforced = true` for **both state and
saved plans**. SOPS protects the passphrase and provider credentials, not the
state itself; a `0600` plaintext `.tfstate` is **not acceptable**. Do not lose
the SOPS age key or the root passphrase: either loss makes state unrecoverable.
For example, create a private SOPS JSON file with `TF_VAR_state_passphrase`
and the root's provider API credential, then run the tasks under
`sops exec-env /absolute/path/to/root.sops.json 'task <root>-plan -- ...'`.
Set `SOPS_AGE_KEY_FILE` to the backed-up age private key path. Never invoke
`tofu state pull > file`: it **decrypts** state to stdout.

## First Use

Run each root independently. Do not initialize one root from the other root's
directory or reuse its state path or passphrase. The committed dependency locks require
OpenTofu 1.12 or later (and before 2.0).

```sh
# Copy the local backend example OUTSIDE Git, replace its absolute paths, and
# create the private state directory before init. Keep it backed up encrypted.
task cloudflare-init -- -backend-config=/path/outside/repository/cloudflare-backend.hcl
# Prepare the variables file outside the repository:
#   cp tofu/cloudflare/examples/terraform.tfvars.example \
#      /path/outside/repository/cloudflare.tfvars
# Replace the zone and documentation addresses in the copied variables file.
mise exec -- tofu fmt -check tofu/cloudflare
task test
SOPS_AGE_KEY_FILE=/path/to/age-key.txt sops exec-env /path/to/cloudflare.sops.json 'task cloudflare-plan -- \
  -var-file=/path/outside/repository/cloudflare.tfvars \
  -out=/path/outside/repository/plans/cloudflare-YYYYMMDD.tfplan'
SOPS_AGE_KEY_FILE=/path/to/age-key.txt sops exec-env /path/to/cloudflare.sops.json 'task cloudflare-show -- \
  /path/outside/repository/plans/cloudflare-YYYYMMDD.tfplan'
```

Repeat for Tailscale with `task tailscale-init`, `task tailscale-plan`, and its
own backend file, state path, passphrase, and variable file. The example identity values
are placeholders and must be replaced with real Tailscale identities.
Before the first Tailscale imports or normal plan, establish its durable tailnet
identity using the adoption procedure below.
`records` is deliberately required to contain at least one Cloudflare record:
omitting the variable file or passing `{}` fails validation instead of
producing a delete-all plan.

Replace documentation-only addresses with the operator-selected ingress node's
public addresses. Enable the example A record only if that node has a public
IPv4 address; include an AAAA record only if it has public IPv6. Review every
declared address family before planning.

Run `tailscale-identity-init`, imports, plan/show/apply, and key export under
the matching `sops exec-env` file as well; without that root's passphrase,
identity establishment and imports cannot read encrypted state.

Review the saved plan before applying. Apply that exact reviewed artifact; do
not run a second plan+apply, which creates and applies a new plan instead.

```sh
SOPS_AGE_KEY_FILE=/path/to/age-key.txt sops exec-env /path/to/cloudflare.sops.json 'task cloudflare-apply -- /path/outside/repository/plans/cloudflare-YYYYMMDD.tfplan'
```

The tasks require saved plan paths to be absolute and outside the repository;
paths are resolved through symlinks and `..` before checking. Use an existing
artifact directory owned by you, without group/other write access. Each output
name must be new: existing files, directories, and output symlinks are refused.
Plans and state snapshots are published atomically with mode `0600` from
exclusively created private temporary files. Plan files can reveal resource
configuration. Use `task cloudflare-drift-plan`
or `task tailscale-drift-plan` with an external `-out` path when inspecting
drift without changing provider resources, and review that artifact in the same
way.

Each OpenTofu subprocess runs from a new private **external** configuration
snapshot, with the initialized root's data directory and backend. Relative
variable-file paths are not supported; use absolute external files. Execution
directories live under `$XDG_STATE_HOME/cvp/tofu` (normally
`~/.local/state/cvp/tofu`), or `CVP_TOFU_RECOVERY_DIR`. The recovery directory
must be owned by you, mode `0700`, with trusted directory ancestry. Successful
execution directories are removed. Failed or interrupted executions retain the
configuration snapshot, private stdout/stderr, and any recovery state; apply
also retains the exact input plan. Failed command output is not echoed into
terminal or automation logs. The wrapper reports the retained directory.

If a backend write fails after resource changes, **do not rerun apply**. Inspect
the reported private directory for `errored.tfstate`; verify the original
backend/workspace and follow a reviewed state-recovery procedure before any
further mutation. If OpenTofu could not write that file, its raw-state fallback
is in the private `stderr.log` instead. Preserve the entire directory until
recovery is complete, and do not paste these logs into tickets or CI output.
The wrapper's failure logs are private but **not SOPS-encrypted** and can contain
secrets (including raw-state fallbacks); encrypt retained recovery material for
off-host storage. Never treat `0600` alone as encryption.

Keep the plan's adjacent `.cvp.json` binding file with the plan. Show and apply
verify the artifact hash, repository root, initialized backend configuration,
and workspace, then operate on a private copy of the verified bytes. A moved
checkout, reconfigured backend, or old unbound plan requires a fresh plan and
review. This binding detects accidental mix-ups; it does not certify human
review or protect against an operator who can rewrite both files.
Binding format 2 also requires regeneration of older format-1 plans. Backend
endpoint/shared-configuration overrides are rejected rather than silently
changing the effective destination behind the binding. Local backends are the
operational default and require explicit absolute external `path` and
`workspace_dir` settings. The backend initialization cache is not the state
file. Back up each encrypted state file and its SOPS-protected passphrase
separately. Remote backends are an optional, reviewed future migration.

The wrapper rejects `TF_CLI_ARGS*`, targeted/excluded plans, mode overrides,
unlocked operations, and additional output flags. Pass supported variable,
lock-timeout, parallelism, and display options explicitly. `-detailed-exitcode`
retains OpenTofu's exit status 2 for a successful plan containing changes.
`TF_LOG*` and `TOFU_LOG*` settings are rejected too, including `TF_LOG_PATH`:
ambient debug logging must not introduce an unvalidated output destination.

## Enrollment Keys

After inventorying and importing the existing tailnet ACL and DNS, add only
the next node to `enrollment_keys` in the Tailscale variables file. For example,
`eve282 = { tags = ["tag:k3s", "tag:k3s-ingress"] }` if Eve is confirmed as
the ingress host. The provider creates a preauthorized, single-use key with a
one-hour expiry; it lives in encrypted OpenTofu state. Review the bound plan
before applying it. Keys are **not** auto-recreated after use or expiry; rotate
deliberately after review. An OAuth/API credential authorized to create keys
and assign the selected tags is still required for the provider.

Export only that key directly to a SOPS/age-encrypted external JSON file:

```sh
SOPS_AGE_KEY_FILE=/path/to/age-key.txt sops exec-env /path/to/tailscale.sops.json \
  'task tailscale-export-enrollment-key -- eve282 /private/eve282.sops.json age1YOUR_PUBLIC_RECIPIENT'
```

The export never prints the key or writes a plaintext key file. The current
`node-join`/`init` interfaces need a private plaintext auth-key file at join
time. Stage it in a short-lived, restricted tmpfs directory and remove it
immediately after join. In one Bash shell (replace node, recipient, and endpoint):

```sh
set -euo pipefail
umask 077
export SOPS_AGE_KEY_FILE=/path/to/age-key.txt
key_dir="$(mktemp -d /dev/shm/cvp-enroll.XXXXXX)"
trap 'rm -f "$key_dir/auth-key"; rmdir "$key_dir"' EXIT
sops decrypt /private/node1.sops.json |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["TAILSCALE_AUTH_KEY"])' > "$key_dir/auth-key"
task init -- --address node.example.net --ssh-port 12345 \
  --tailscale-auth-key-file "$key_dir/auth-key"
```

`/dev/shm` must actually be tmpfs on the controller; check before staging.
The wizard will not paste or persist a new key itself. Do **not** commit the
encrypted operator JSON to the cluster GitOps path:
it is an operator credential, not a Kubernetes Secret.

## Deletion Safeguards

All Cloudflare records, the Tailscale ACL, the Tailscale DNS configuration, and
enrollment keys
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
  -var-file=/path/outside/repository/cloudflare.tfvars \
  'cloudflare_dns_record.public["ingress_a"]' ZONE_ID/RECORD_ID
```

For a new, empty Tailscale state, establish the identity **before either
import**. This guarded operation is intentionally separate from normal plans.
Run it through its task, which points the operation at this root's per-instance
state directory (`TF_DATA_DIR`); a raw wrapper invocation without that
environment cannot find the initialized backend:

```sh
task tailscale-identity-init -- \
  YOUR_EXPLICIT_TAILNET_ID_OR_DOMAIN \
  -var-file=/path/outside/repository/tailscale.tfvars
```

It accepts only empty state, produces a fixed identity-only plan, verifies that
the sole change is creation of the builtin `terraform_data.tailnet_identity`,
and applies those inspected bytes under normal state locking. It cannot apply
external resource changes or replace an existing identity. The tailnet argument
is authoritative for establishment; use that same explicit value in subsequent
variable files. Generic `-target`/`-exclude` options remain forbidden.

Tailscale policy and DNS imports then use the provider resource IDs:

```sh
task tailscale-import -- -var-file=/path/outside/repository/tailscale.tfvars \
  tailscale_acl.policy acl
task tailscale-import -- -var-file=/path/outside/repository/tailscale.tfvars \
  tailscale_dns_configuration.tailnet dns_configuration
```

Use an explicit tailnet ID/domain, never the credential-relative `-` alias.
Both singleton resources depend on the protected tailnet identity. The wrapper
checks the effective tailnet against that established identity before import
or planning, pins the checked value for the operation, and inspects saved plans
locally to refuse singleton creation or identity changes: import both ACL
and DNS first. The DNS provider's create operation replaces existing remote
DNS configuration, so an ACL creation failure alone would not protect DNS.
Direct OpenTofu commands bypass this wrapper adoption gate.

Existing states with a correctly populated identity need no identity migration.
An old state containing imported singletons but no identity is rejected. Freeze
all writers, take private state and remote-policy/DNS snapshots, and review the
original tailnet before migration. One explicit migration is to relinquish the
old state's singleton ownership without deleting remote objects, establish the
identity in the now-empty state, then re-import those same objects for the
verified tailnet. Use the State Handoff safeguards below; do not invent an
identity for already-imported objects or use targeting to bypass the rejection.

Inspect the resulting plan after each import. Do not use `-target` as a normal
deployment method, and do not enable overwrite flags to bypass an inventory.

### State Handoff

If transferring ownership between roots, freeze the source Terraform/OpenTofu
automation before the handoff: disable its
scheduled and CI applies, revoke or pause any other apply path, and keep it
frozen until the new root has applied cleanly and the old state no longer owns
the resources. Two active states must never manage the same external object.

Never use `tofu state pull > file`, `state -state-out=...`, or the former
`task <root>-state-pull`: these publish **plaintext** state. An encrypted local
state backup is a copy of the encrypted backend file, not OpenTofu's decrypted
`state pull` output. Migrations and splits need an explicitly reviewed procedure
that keeps intermediate artifacts encrypted throughout; none is automated here.
Stop and design that procedure before a backend migration or handoff rather than
using commands that briefly write plaintext state.

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

- `group:admin` to `tag:k3s`: Kubernetes API `6443`.
- `group:admin` to `tag:k3s-ingress`: internal applications on `80`, `443`.
- `tag:ci` (and `group:ci` when explicitly populated) to `tag:k3s`:
  Kubernetes API `6443` only. An empty `ci_users` omits the human CI group;
  it does not invent a CI login or disable the future tagged CI device path.

SSH (`22`) is never granted over the tailnet; the policy tests assert that it is
denied. Nodes accept SSH only on their public addresses.

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

The local backend examples are placeholders only. No backend state, credentials, or
generated plan belongs in Git. The generated `.terraform.lock.hcl` files are
provider selections and should remain committed for reproducible initialization.

The repository's root `.gitignore` covers HCL and JSON variable files
(`*.tfvars`, `*.tfvars.json`, `*.auto.tfvars.json`) and backend files
(`*.tfbackend`, `*.tfbackend.json`, `backend.hcl`, `*.backend.*`). Keep any
other state-bearing artifacts outside the repository; this runbook does not
modify root-level ignore rules.
