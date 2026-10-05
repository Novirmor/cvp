variable "tailnet" {
  description = "Tailnet ID or domain to configure."
  type        = string
  nullable    = false

  validation {
    condition     = var.tailnet != "" && var.tailnet != "-" && var.tailnet == trimspace(var.tailnet)
    error_message = "tailnet must be an explicit tailnet ID or domain; the credential-relative '-' alias is forbidden."
  }
}

variable "admin_users" {
  description = "Tailscale identities allowed to administer the K3s nodes."
  type        = list(string)
  nullable    = false

  validation {
    condition = length(var.admin_users) > 0 && alltrue([
      for user in var.admin_users : user != "" && user == trimspace(user)
    ])
    error_message = "admin_users must contain at least one non-empty Tailscale identity."
  }
}

variable "ci_users" {
  description = "Tailscale identities representing CI operators or CI service users."
  type        = list(string)
  nullable    = false

  validation {
    condition = length(var.ci_users) > 0 && alltrue([
      for user in var.ci_users : user != "" && user == trimspace(user)
    ])
    error_message = "ci_users must contain at least one non-empty Tailscale identity."
  }
}

variable "magic_dns" {
  description = "Whether Tailscale MagicDNS is enabled for the tailnet."
  type        = bool
  nullable    = false
}

variable "override_local_dns" {
  description = "Whether configured global nameservers override each device's local DNS."
  type        = bool
  nullable    = false
}

variable "dns_nameservers" {
  description = "Global IPv4 or IPv6 nameservers for the tailnet."
  type = list(object({
    address            = string
    use_with_exit_node = optional(bool, false)
  }))
  nullable = false

  validation {
    condition = (!var.override_local_dns || length(var.dns_nameservers) > 0) && alltrue([
      for nameserver in var.dns_nameservers :
      can(cidrhost("${nameserver.address}/32", 0)) || can(cidrhost("${nameserver.address}/128", 0))
    ])
    error_message = "dns_nameservers entries must be valid IPv4 or IPv6 addresses, and at least one entry is required when override_local_dns is true (empty is allowed for MagicDNS or device-local DNS)."
  }
}

variable "search_paths" {
  description = "Additional DNS search paths; MagicDNS supplies the tailnet domain automatically."
  type        = list(string)
  nullable    = false
  default     = []

  validation {
    condition = alltrue([
      for path in var.search_paths :
      can(regex("^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$", path))
    ])
    error_message = "search_paths must contain DNS domain names without whitespace or a trailing dot."
  }
}

variable "split_dns" {
  description = "Explicit split-DNS rules keyed by a stable local name."
  type = map(object({
    domain = string
    nameservers = list(object({
      address            = string
      use_with_exit_node = optional(bool, false)
    }))
  }))
  nullable = false
  default  = {}

  validation {
    condition = alltrue(flatten([
      for rule in values(var.split_dns) : [
        can(regex("^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$", rule.domain))
        && length(rule.nameservers) > 0
        && alltrue([
          for nameserver in rule.nameservers :
          can(cidrhost("${nameserver.address}/32", 0)) || can(cidrhost("${nameserver.address}/128", 0))
        ])
      ]
    ]))
    error_message = "Each split-DNS rule needs a valid domain and at least one valid IPv4 or IPv6 nameserver."
  }

  validation {
    condition     = length(distinct([for rule in values(var.split_dns) : rule.domain])) == length(var.split_dns)
    error_message = "split_dns domains must be unique across entries; merge the resolvers for a duplicated domain into a single entry, because the provider silently overwrites duplicate domains."
  }
}
