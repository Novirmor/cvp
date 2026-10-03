output "public_records" {
  description = "Identifiers and effective names of the explicitly managed public records."
  value = {
    for key, record in cloudflare_dns_record.public : key => {
      id       = record.id
      hostname = record.name
      type     = record.type
      proxied  = record.proxied
    }
  }
}
