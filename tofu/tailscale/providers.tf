provider "tailscale" {
  tailnet = var.tailnet

  # Authentication is supplied out of band through TAILSCALE_API_KEY or the
  # provider's OAuth environment variables. No credential is stored here.
}
