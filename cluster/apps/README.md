# Applications

The only application overlay currently present is a suspended, opt-in smoke
overlay. Its Nginx image is pinned to the official Docker Hub manifest digest,
but it remains a non-production template. Before creating a production overlay:

- Build the application image in its application repository.
- Pin it to a reviewed immutable digest.
- Replace `example.invalid` with a real name and provide its TLS Secret through
  an encrypted SOPS manifest or another approved certificate path.
- Add application-specific egress rules and backup/restore resources.
- Keep the Flux `apps` Kustomization suspended until those checks pass.

The base has no custom resource or application manifest abstraction.
