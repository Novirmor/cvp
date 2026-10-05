# Ingress Relocation Runbook

Move the public ingress plane — the IPv6 frontend, the ServiceLB and Traefik
placement, and the external DNS target — from the operator-selected ingress
node to another inventory node. This is a maintenance and recovery
action: the procedure must complete without changing any application manifest
(PLAN.md exit gate G6).

## What defines the ingress node

Four declarations must move together, and only the first three live in this
repository's Ansible inventory:

1. Membership in the `ingress` group in `ansible/inventory/hosts.yml`; the
   `ingress_v6` role installs the systemd socat forwarders that bridge public
   IPv6 `:80`/`:443` to the local IPv4 ServiceLB listeners.
2. The node labels in the host's `inventory/host_vars/<node>.yml`:
   `cvp.io/ingress=true` (Traefik's node selector in the committed
   `HelmChartConfig`), plus `svccontroller.k3s.cattle.io/enablelb=true` and
   `svccontroller.k3s.cattle.io/lbpool=public` (the ServiceLB allow-list).
3. The Tailscale tag `tag:k3s-ingress` in `tailscale_advertise_tags`, which
   the ACLs grant ingress-testing access on ports 80 and 443.
4. The Cloudflare record that points the public hostname at the node's public
   address; this is owned by `tofu/cloudflare` (see `tofu.md`).

`site.yml` reconciles node labels through the Kubernetes API and removes the
obsolete managed labels from the retired node automatically. Nothing removes
the retired node's socat units or closes its firewall ports by itself; step 3
below does both explicitly so only the new node accepts public 80 and 443.

## Preconditions

- The target node is joined ([nodes.md](nodes.md)), converged, healthy in
  the WireGuard mesh, and reachable over Tailscale.
- The target node has a stable public address for the Cloudflare record, and
  nothing of its own is bound to `[::]:80` and `[::]:443`.
- The change is reviewed as one inventory diff plus one reviewed OpenTofu
  plan; the Cloudflare root's `prevent_destroy` guard stays in place.
- Arrange a maintenance window. Traefik currently has a single replica and
  `externalTrafficPolicy: Local`: moving its only pod interrupts the old
  ingress path before DNS can point clients at the new one. This procedure
  does not promise a zero-downtime cutover.

## Procedure

1. Commit the inventory change: move the target node into the `ingress`
   group, move the three labels from the old node's `k3s_node_labels` to the
   target's, and move `tag:k3s-ingress` between the hosts'
   `tailscale_advertise_tags`. In the retired node's host_vars, set
   `firewall_public_ingress_ports: []` so nftables stops accepting public
   80/443 there (the group default keeps them open on the target).
2. Converge: `task site`. The label reconciliation demotes the old node and
   promotes the target; the `ingress_v6` role installs the forwarder units on
   the target. Node-label changes alone do **not** evict a running Traefik
   pod. Restart its Deployment after the labels have converged:

   ```sh
   kubectl -n kube-system rollout restart deploy/traefik
   kubectl -n kube-system rollout status deploy/traefik
   ```

   Confirm the new pod runs on the target node before continuing; if it
   cannot schedule there, stop and roll back rather than cutting DNS.
3. Retire the old frontend on the previous ingress node so the relocation is
   complete rather than merely duplicated:

   ```sh
   ssh <old-node> sudo systemctl disable --now cvp-ingress-v6-80.service cvp-ingress-v6-443.service
   ssh <old-node> sudo rm /etc/systemd/system/cvp-ingress-v6-{80,443}.service
   ```

4. Verify the cluster side before touching DNS. `externalTrafficPolicy:
   Local` requires Traefik itself to run on the ingress node:

   ```sh
   kubectl -n kube-system get pods -o wide | grep traefik
    kubectl -n kube-system get ds -l svccontroller.k3s.cattle.io/svcname=traefik,svccontroller.k3s.cattle.io/svcnamespace=kube-system -o wide
    python3 scripts/cluster-ingress-ready --context reviewed-cluster-context --timeout 5m
   ```

   The traefik pod must be ready on the target node and the svclb-traefik
   DaemonSet must have a ready pod there. Probe the public port on the target
   directly before touching DNS; `task verify` alone does not validate ingress
   placement or external routing. Also confirm the K3s helm-controller
    rendered the unchanged `HelmChartConfig` (see `cluster.md`). The readiness
    helper checks the deployed chart/values, completed chart Job, rollout, and
    Ready local endpoints; it does not probe the public path. Keep Service
    NodePort allocation enabled because the pinned K3s ServiceLB uses those
    ports for `externalTrafficPolicy: Local`.

5. Cut over DNS through the Cloudflare root following `tofu.md`: change the
   record content to the target node's public address, update every declared
   address family in the same reviewed plan, apply the plan, and confirm the
   record resolved externally.
6. Verify the public route end to end from an external vantage point: the
   HTTP-to-HTTPS redirect targets the public port 443, and the certificate is
   served. Then record the relocation as gate evidence.

## Rollback

Restore the old node's inventory labels, `ingress` membership, firewall
opening, and socat units first; converge and restart Traefik as in step 2.
Verify the old node once again has a ready Traefik pod and local ServiceLB
endpoint, then point DNS back to it. Application manifests do not change;
the Traefik Deployment restart is necessary in both directions.

## After a node loss

When the ingress node is gone rather than retired, start from the recovery
order in `cluster/README.md`: rebuild or replace the node (or promote a
survivor with the labels above), verify Traefik and the svclb endpoint are
local to the new ingress node, and only then cut DNS. Do not point DNS at a
node whose svclb pod is not ready; `externalTrafficPolicy: Local` will black-
hole the traffic.
