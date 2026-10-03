output "acl_policy_id" {
  description = "The Tailscale ACL policy resource ID."
  value       = tailscale_acl.policy.id
}

output "dns_configuration_id" {
  description = "The Tailscale DNS configuration resource ID."
  value       = tailscale_dns_configuration.tailnet.id
}

output "managed_tags" {
  description = "Tags defined by the policy and expected on the K3s and CI devices."
  value       = ["tag:k3s", "tag:k3s-ingress", "tag:ci"]
}

output "allowed_tcp_ports" {
  description = "The intentionally small Tailscale port surface."
  value = {
    admin = [22, 6443, 80, 443]
    ci    = [6443]
  }
}
