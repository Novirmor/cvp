provider "cloudflare" {
  # Authentication is supplied out of band through CLOUDFLARE_API_TOKEN.
  # Use a token scoped to the zone with DNS Read and DNS Write permissions.
}
