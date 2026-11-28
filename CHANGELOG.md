# Changelog

This module follows semantic versioning. Before v1, a minor version may
change the API; each such change says what callers must do.

## v0.2.0 (2026-11-28)

- Requires Go 1.27, the newest Go release; Go 1.26 is no longer
  supported.
- CI runs staticcheck and govulncheck at the versions pinned in
  `tools/go.mod`, a module of its own that importers never see.
- ParsePassphraseDocument uses `encoding/json/v2`: member names match
  exactly, and duplicate members are refused. Documents written by this
  package are unchanged.

## v0.1.1 (2026-11-28)

- A source that fails to read, in the header or a frame, now fails with
  its own error instead of `ErrDecrypt`, so a dropped connection is no
  longer reported as a damaged object. An object that ends early is still
  `ErrDecrypt`, including a source that fails with `io.ErrUnexpectedEOF`, as a
  truncated HTTP body does. A caller that treated every `ErrDecrypt` as damage needs no
  change; one that relied on read failures wrapping `ErrDecrypt` should
  check for the source's error.
- `KeyWrapper`'s methods and every `PassphraseDocument` field have doc
  comments, and DESIGN.md explains the format and its choices.
- CI also checks formatting, `go mod tidy -diff`, and `govulncheck`.

No API change.

## v0.1.0 (2026-11-27)

First release.

- `Format.NewWriter` and `Format.NewReader` stream objects encrypted with
  AES-256-GCM in 1 MiB frames, each object under its own HKDF-derived key,
  with reordering, splicing, and truncation detected.
- `LocalKEK` wraps data keys with a key-encryption key, and
  `Format.WrapWithPassphrase` wraps a KEK with an Argon2id passphrase into
  a `PassphraseDocument`.
- Format version 2 is frozen; golden files pin it.
