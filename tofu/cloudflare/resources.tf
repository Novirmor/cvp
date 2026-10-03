resource "cloudflare_dns_record" "public" {
  for_each = var.records

  zone_id = var.zone_id
  name    = each.value.name
  type    = each.value.type
  content = each.value.content

  # Automatic TTL is required for proxied records. The variable validation
  # prevents an accidental non-automatic TTL in that case.
  ttl      = each.value.ttl
  proxied  = each.value.proxied
  priority = each.value.priority
  comment  = each.value.comment
  tags     = each.value.tags

  # Existing records must be imported before they are declared here. The v5
  # resource has no overwrite escape hatch, so a duplicate create fails.

  lifecycle {
    # Removing a map key is a destructive DNS change and requires an explicit
    # temporary removal of this guard after review.
    prevent_destroy = true
  }
}
