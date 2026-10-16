terraform {
  # Each instance configures its own external, local state and workspace paths.
  # encryption.tf encrypts state and saved plans before they reach disk.
  backend "local" {}
}
