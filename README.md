# envelope

[![Go Reference](https://pkg.go.dev/badge/github.com/jacob2161/envelope.svg)](https://pkg.go.dev/github.com/jacob2161/envelope)
[![CI](https://github.com/jacob2161/envelope/actions/workflows/ci.yml/badge.svg)](https://github.com/jacob2161/envelope/actions/workflows/ci.yml)

Envelope encryption for objects of any size: AES-256-GCM in 1 MiB frames, a
fresh key per object, and data keys wrapped by a key-encryption key (KEK) or a
passphrase.

```bash
go get github.com/jacob2161/envelope
```

## Usage

```go
var objects = envelope.Format{Magic: "APPE", Label: "my application"}

writer, err := objects.NewWriter(file, "data-key-1", dataKey)
if err != nil {
	return err
}
if _, err := io.Copy(writer, plaintext); err != nil {
	return err
}
if err := writer.Close(); err != nil { // seals the final frame
	return err
}

reader, err := objects.NewReader(file, func(keyID string) ([]byte, error) {
	return kek.Unwrap(wrappedDataKeys[keyID])
})
if err != nil {
	return err
}
// Plaintext arrives frame by frame; only a nil error at the end means the
// whole object was authentic. Write to a staging file when a partial
// object must never be used.
if _, err := io.Copy(staging, reader); err != nil {
	return err
}
```

## Format

```
object = magic[4] u16 version u16 key_id_length key_id salt[32] frame*
frame  = u32 ciphertext_length ciphertext
```

- Each object's key is HKDF-SHA256(data key, salt, label + " object v2"), so
  nonces never repeat across objects however many share a data key.
- Frame i uses nonce `u32(0) || u64(i)` and authenticates the header, i, and
  whether it is the final frame: reordering, splicing frames between objects,
  truncation, and appended bytes all fail.
- A `Format`'s magic and label together separate one application's objects,
  KEKs, and passphrase documents from every other's.
- An object holds at most 2^32 frames (about 4 PiB), so no nonce repeats.
- Passphrase documents are bounded (16 KiB, exact salt and key sizes, at most
  256 MiB and 16 Argon2id passes) before any key is derived.
- `KeyWrapper` is the seam for a KMS or Vault Transit; `LocalKEK` keeps the
  KEK in memory. `PassphraseDocument` recovers a KEK from a passphrase with
  Argon2id; passphrase policy is yours.
- Streams at about 2.6 GB/s on one modern core, reusing its frame buffers.

The golden objects in `testdata` are checked in and must open unchanged in
every later version.

Tested on the two newest Go releases. Licensed under the MIT license.
