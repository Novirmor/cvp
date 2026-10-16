variable "state_passphrase" {
  description = "Separate high-entropy passphrase for this root's state and plans. Supply through TF_VAR_state_passphrase from SOPS/age."
  type        = string
  sensitive   = true
  nullable    = false

  validation {
    condition     = length(var.state_passphrase) >= 32
    error_message = "state_passphrase must have at least 32 characters."
  }
}

terraform {
  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }
    state {
      method   = method.aes_gcm.state
      enforced = true
    }
    plan {
      method   = method.aes_gcm.state
      enforced = true
    }
  }
}
