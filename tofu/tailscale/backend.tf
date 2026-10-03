terraform {
  # This root has its own state. Configure the backend with -backend-config;
  # no bucket, credentials, or live state belong in this repository.
  backend "s3" {}
}

# Example backend configuration (use a private, encrypted state bucket):
#
#   tofu init -backend-config=examples/backend.hcl
#
# The example file contains placeholders only. The Tailscale and Cloudflare
# roots intentionally use different backend keys.
