# SOPS and age

Secret payloads are encrypted in Git with SOPS and age. The age private key is
never stored in this repository. An operator-chosen external secrets store
holds the recovery copy of that private key; Bitwarden Secrets Manager is an
optional example.

## Bootstrap

1. Generate one age key pair outside this repository and store the private key
   in the operator-chosen external secrets store.
2. Put only the public recipient in a local copy of
[`../.sops.yaml.example`](../.sops.yaml.example), or pass it through
`SOPS_AGE_RECIPIENTS`.
3. An operator manually seeds the Flux decryption Secret out of band; Ansible
   does not create, recover, or own it. The key file must be named `age.agekey`
   inside the Secret. `scripts/bootstrap-flux` creates this Secret from its
   required `SOPS_AGE_KEY_FILE` input, or use the equivalent explicit-context
   command below:

   ```sh
    kubectl --context=reviewed-cluster-context -n flux-system create secret generic sops-age \
     --from-file=age.agekey=/path/to/recovered/age.key \
     --dry-run=client -o yaml | kubectl --context=reviewed-cluster-context apply -f -
   ```

4. Encrypt a new Secret manifest with SOPS before adding it to a Kustomize
   overlay. Do not apply the `.example` template directly.

The Flux `apps`, `data`, and `operations` Kustomizations reference `sops-age`
for decryption. A missing key is an intentional recovery/bootstrap failure,
not a reason to commit the private key.

## Template

[`templates/example-secret.sops.yaml.example`](templates/example-secret.sops.yaml.example)
contains placeholders only. Create a real file with a `.sops.yaml` suffix,
encrypt it with the cluster's age recipient, and add that real file to the
appropriate overlay only after reviewing the rendered resource locally.

`scripts/test-manifests` rejects plaintext Secret payloads and Kustomize
`secretGenerator` inputs, including standalone builtin SecretGenerators. Missing,
null, or malformed Secret metadata cannot suppress the plaintext-payload checks.
Use encrypted Secret resources instead of generators. Empty Secrets without
payloads are allowed. Generic `List` and typed list wrappers such as
`SecretList` are rejected, including in unreferenced source files; use separate
manifest documents instead. Source files and rendered overlays are checked before
schema validation removes SOPS metadata and substitutes empty payload values
in a temporary validation-only stream. The encrypted files stay unchanged.

These checks verify encryption structure, not authenticity or decryptability;
only Flux with the recovered identity can verify a production SOPS MAC. The
credential-free regression tests generate a disposable age identity and perform
a real encryption/decryption round-trip; they never use the production identity.
