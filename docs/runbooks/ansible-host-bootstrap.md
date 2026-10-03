# Host Bootstrap Runbook

All commands run from the repository root via the Taskfile. This is the initial
bootstrap procedure; `task onboard` adds subsequent nodes only after the control
plane exists.

The default inventory contains no hosts and provisions none. Both
`k3s_cluster_init_host` and `k3s_server_host` are empty by default. Before any
host operation:

- Copy `ansible/inventory/host_vars/example-newnode.yml.example` to a host_vars
  file for the operator-selected initial server (example `server1.yml`). Fill
  its SSH endpoint, matching `node_name`, pinned virtualization type, WireGuard
  public key and endpoint, placement labels, and storage intent.
- Register that server in `wireguard` and `k3s_servers` in
  `ansible/inventory/hosts.yml`, and in `ingress` if selected for public ingress.
- Set `k3s_cluster_init_host` in `ansible/inventory/group_vars/all.yml` and
  `k3s_server_host` in `ansible/inventory/hosts.yml`'s `all.vars` to the selected
  inventory name (example `server1`), and set that host's `k3s_role: server` and
  `k3s_server_init: true`. Only one server initializes the cluster.
- Assign a mesh address (synthetic example `192.0.2.1` in `192.0.2.0/24`) and
  include required API TLS SANs. Replace synthetic values before use. Supply
  private keys and enrollment credentials from an operator-chosen external
  secrets store or external vars file.

1. Confirm the hosts resolve over the operator's bootstrap SSH path, verify
   their SSH host fingerprints, and confirm the inventory endpoints are their
   current stable WireGuard endpoints. Host-key checking stays enabled.
2. For each **new** host, use `task prepare-access` as described in
   `node-onboarding.md`. It needs initial root SSH access and installs only
   Python, sudo, and the tools required for the read-only `task probe`.
   It creates the `ops` account, installs its approved public key, and
   verifies SSH and sudo without touching host network policy.
3. Complete the read-only compatibility check: `task probe`. It does not
   require WireGuard yet.
4. Review the convergence: `task site -- --check --diff`.
5. Prepare a Tailscale auth key from the operator's external secrets store at
   runtime; never add it to inventory or Git.
6. Apply with those runtime inputs and a temporary trusted SSH CIDR if Tailscale
   is not already enrolled:
   `task site -- -e '{"firewall_ssh_ipv4_source_cidrs":["<operator-ip>/32"]}'`.
7. Run `task probe-wireguard` after convergence to test mesh peers and path
   MTU, then `task verify`. Record WireGuard handshakes, firewall state, K3s
   service state, live sysctls, and the Flannel MTU.
8. After subsequent nodes join through `node-onboarding.md`, exercise large
   cross-node TCP and UDP transfers before accepting the `1370` pod MTU assumption.
9. Enable K3s backup only after supplying an age recipient and an off-host
   upload command (see `ansible/README.md`), then perform a disposable restore
   drill via `task restore-k3s`.

The `site.yml` playbook is the host mutation boundary. It does not apply
ordinary Kubernetes resources or bootstrap Flux.
