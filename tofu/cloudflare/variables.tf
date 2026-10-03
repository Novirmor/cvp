variable "zone_id" {
  description = "The Cloudflare zone ID containing the explicitly managed records."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a 32-character lowercase hexadecimal Cloudflare zone ID."
  }
}

variable "records" {
  description = "Non-empty set of public DNS records to manage. Every record must be declared explicitly."
  type = map(object({
    name     = string
    type     = string
    content  = string
    ttl      = optional(number, 300)
    proxied  = optional(bool, false)
    priority = optional(number)
    comment  = optional(string)
    tags     = optional(set(string), [])
  }))
  nullable = false

  validation {
    condition = alltrue([
      for key, record in var.records :
      trimspace(key) != ""
      && contains(["A", "AAAA", "CAA", "CNAME", "MX", "NS", "TXT"], record.type)
      && trimspace(record.name) != ""
      && trimspace(record.content) != ""
      && (record.type != "A" || can(cidrhost("${record.content}/32", 0)))
      && (record.type != "AAAA" || can(cidrhost("${record.content}/128", 0)))
      && (record.type != "CNAME" || can(regex("^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\\.?$", record.content)))
      && (record.ttl == 1 || (record.ttl >= 60 && record.ttl <= 86400))
      && (!record.proxied || contains(["A", "AAAA", "CNAME"], record.type))
      && (!record.proxied || record.ttl == 1)
      && (record.type != "MX" || record.priority != null)
    ])
    error_message = "Record keys, names, and content must be non-empty. Records must use a supported uppercase type with content matching that type (IPv4 for A, IPv6 for AAAA, a hostname for CNAME), a TTL of 1 or 60-86400, and a priority for MX records; only A, AAAA, and CNAME records may be proxied, and proxied records must use TTL 1."
  }

  validation {
    condition     = length(var.records) > 0
    error_message = "records must contain at least one explicitly managed DNS record; an empty map is rejected to prevent an accidental delete-all plan."
  }
}
