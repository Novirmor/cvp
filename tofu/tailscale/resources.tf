locals {
  # The policy deliberately contains only the ports used by the new K3s
  # architecture. WireGuard-only cluster ports are not Tailscale permissions.
  policy = {
    groups = {
      "group:admin" = var.admin_users
      "group:ci"    = var.ci_users
    }

    tagOwners = {
      "tag:k3s"         = ["group:admin"]
      "tag:k3s-ingress" = ["group:admin"]
      "tag:ci"          = ["group:admin"]
    }

    acls = [
      {
        action = "accept"
        proto  = "tcp"
        src    = ["group:admin"]
        dst = [
          "tag:k3s:22",
          "tag:k3s:6443",
          "tag:k3s-ingress:80",
          "tag:k3s-ingress:443",
        ]
      },
      {
        action = "accept"
        proto  = "tcp"
        src    = ["group:ci", "tag:ci"]
        dst    = ["tag:k3s:6443"]
      },
    ]

    # These assertions prevent later policy edits from granting CI
    # administrative or ingress access.
    tests = [
      {
        src   = "group:admin"
        proto = "tcp"
        accept = [
          "tag:k3s:22",
          "tag:k3s:6443",
          "tag:k3s-ingress:80",
          "tag:k3s-ingress:443",
        ]
      },
      {
        src    = "group:ci"
        proto  = "tcp"
        accept = ["tag:k3s:6443"]
        deny = [
          "tag:k3s:22",
          "tag:k3s-ingress:80",
          "tag:k3s-ingress:443",
        ]
      },
      {
        src    = "tag:ci"
        proto  = "tcp"
        accept = ["tag:k3s:6443"]
        deny = [
          "tag:k3s:22",
          "tag:k3s-ingress:80",
          "tag:k3s-ingress:443",
        ]
      },
    ]
  }
}

# Guard against silently retargeting this root at a different tailnet.
# Changing the provider's tailnet setting re-points existing state at another
# tailnet without tripping the prevent_destroy safeguards on the singleton
# resources below. triggers_replace (not input, which only stores state) makes
# a tailnet change force replacement of this resource, and prevent_destroy
# blocks it, forcing an explicit, reviewed migration instead.
resource "terraform_data" "tailnet_identity" {
  input            = var.tailnet
  triggers_replace = [var.tailnet]

  lifecycle {
    prevent_destroy = true
  }
}

resource "tailscale_acl" "policy" {
  acl = jsonencode(local.policy)

  # Import the existing policy before managing it; a first apply must not
  # overwrite content that was never inventoried. With
  # reset_acl_on_destroy = false, destroying this resource leaves the remote
  # tailnet policy intact; it is not reset to the provider default.
  overwrite_existing_content = false
  reset_acl_on_destroy       = false

  lifecycle {
    # Deletion must stay deliberate: the remote policy survives a destroy but
    # would be silently abandoned, unmanaged and drifting.
    prevent_destroy = true
  }
}

resource "tailscale_dns_configuration" "tailnet" {
  magic_dns          = var.magic_dns
  override_local_dns = var.override_local_dns
  search_paths       = var.search_paths

  dynamic "nameservers" {
    for_each = var.dns_nameservers

    content {
      address            = nameservers.value.address
      use_with_exit_node = nameservers.value.use_with_exit_node
    }
  }

  dynamic "split_dns" {
    for_each = var.split_dns

    content {
      domain = split_dns.value.domain

      dynamic "nameservers" {
        for_each = split_dns.value.nameservers

        content {
          address            = nameservers.value.address
          use_with_exit_node = nameservers.value.use_with_exit_node
        }
      }
    }
  }

  lifecycle {
    # This resource owns the complete tailnet DNS configuration.
    prevent_destroy = true
  }
}
