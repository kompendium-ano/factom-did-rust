# factom-did-rust
![Rust](https://github.com/kompendium-ano/factom-did-rust/workflows/Rust/badge.svg)

The `client` module enables:

- creation of a new DID
- addition of management key(s) for the DID
- addition of DID key(s) for the DID
- addition of service(s) for the DID
- export of public metadata to be recorded on Factom
- encryption of the newly created keys
- update of an existing DID: adding/revoking management keys, DID keys and services and producing a signed DID

The `resolver` module contains a pure-data library for re-constructing the effective DID Document from a list of DID
entries. It is a complete implementation of the resolver specification in https://github.com/bi-foundation/FIS/blob/feature/DID/FIS/DID.md
