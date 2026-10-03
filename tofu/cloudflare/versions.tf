terraform {
  # The committed dependency lock file is maintained with OpenTofu 1.12.
  required_version = ">= 1.12.0, < 2.0.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.25"
    }
  }
}
