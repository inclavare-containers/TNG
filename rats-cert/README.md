# rats-cert

This crate was migrated from [rats-rs](https://github.com/inclavare-containers/rats-rs/tree/eb6d630a7a44974c8dff34d418022354765e1262/rats-cert) and integrated into the TNG workspace.

## Migration Notes

- Original repository: https://github.com/inclavare-containers/rats-rs
- Source commit: `eb6d630a7a44974c8dff34d418022354765e1262`
- Original path: `rats-cert/`

## Policy Configuration

The builtin Attestation Service (`as_type` = `"builtin"`) appraises evidence with an OPA/Rego policy. The policy variant is selected by the `attestation_policy.type` field. Besides the built-in `default`/`hardware_only`/`hardware_only_strict`/`hardware_with_reference_values`/`trust_all` postures, the `inline`/`path` custom-policy escapes are also supported.
