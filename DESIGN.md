# Design

Envelope encrypts objects of any size so they can be streamed, stored for
years, and read back only with the right key. This document says how the
format works and why it is built this way. The package documentation states
the API; the golden files in `testdata/` pin the bytes.

## Keys

There are three layers of keys.

- A **KEK** (key-encryption key) is a 32-byte AES-256 key the application
  holds, usually from an operator or a secret store. It never encrypts an
  object; it only wraps data keys. `LocalKEK` holds one in memory.
- A **data key** is a random 32-byte key from `NewDataKey`. The application
  stores it wrapped by the KEK (`KeyWrapper.Wrap`) and names it by an ID of
  its choosing, which every object header carries. Rotating the KEK means
  rewrapping data keys, not re-encrypting objects.
- An **object key** is derived for each object:
  HKDF-SHA256(data key, salt, label + " object v2"), with a random 32-byte
  salt in the object's header. No two objects share an AES key, however many
  share a data key.

A KEK can also be wrapped with a passphrase into a `PassphraseDocument`, so
an operator who loses the KEK but keeps the document and the passphrase can
recover every object.

## Object format

```
object = magic[4] u16 version u16 key_id_length key_id salt[32] frame*
frame  = u32 ciphertext_length ciphertext
```

Plaintext is cut into 1 MiB frames, each sealed with AES-256-GCM, so a reader
needs one frame of memory whatever the object's size, and a writer can
stream without knowing the length in advance.

- **Nonces.** Frame i uses the nonce u32(0) || u64(i). A counter is safe
  because the key is unique to the object; it saves storing a nonce per
  frame and cannot repeat by chance.
- **Associated data.** Every frame authenticates the whole header, its own
  index, and a final flag. Changing the header, moving a frame, splicing a
  frame from another object, or dropping frames from the end all fail to
  decrypt.
- **Finality.** The writer seals the last frame with the final flag set,
  even when it is empty. A reader accepts the object only after a final
  frame and only if nothing follows it, so truncation at a frame boundary
  is detected rather than read as a shorter object.
- **Limits.** At most 2^32 frames (about 4 PiB), so no index, and no nonce,
  repeats; a writer past it fails with `ErrTooLarge`. A key ID is 1 to 255
  bytes. A frame's length prefix is checked before it is read, so a damaged
  length cannot make the reader allocate more than one frame.

A full-size frame could be either a middle frame or a final one, so the
reader tries it as a middle frame first and, if that fails, as the final
frame. Both attempts read the same ciphertext buffer, which is why the
plaintext buffer is separate.

## Errors

`ErrDecrypt` means the object is damaged: it failed authentication, has an
impossible length, ended early, or has bytes after its final frame. A source
that fails to read (a dropped connection, a disk error) returns its own
error instead, so a caller can retry a read without marking a good object as
damaged. `ErrUnsupportedVersion` says only that a newer writer may have made
the object. `ErrUnknownKey` is for a `KeyLookup` that does not know an ID.

## Formats

A `Format` is an application's magic and label. The label is bound into
every object key, every KEK ID, and every passphrase document, and the magic
is bound through the header, so one application's objects and keys never
open under another's, even with the same key bytes. Changing either makes
everything written before unreadable; an application fixes its `Format`
once.

## Passphrase documents

A passphrase document seals the KEK with AES-256-GCM under a key Argon2id
derives from the passphrase (3 passes over 64 MiB on 4 lanes for new
documents). Every field but `Created` is bound into the ciphertext, so a
document cannot be edited to weaken its parameters. Reading a document
bounds what it may ask for (16 KiB of JSON, 256 MiB and 16 passes), so a
hostile document costs seconds, not the machine.

## Why KeyWrapper is an interface

`LocalKEK` is the only implementation here. The interface is kept because
callers that store wrapped keys hold a `KeyWrapper` rather than a
`*LocalKEK`, so a KMS or Vault Transit client can replace the local KEK
without changing them. Removing it would break those callers for no gain
to anyone else.

## Compatibility

Objects and data keys live for years, so format version 2 is frozen. The
golden files in `testdata/` were written once and must open unchanged in
every later version; they are never regenerated. A change to the format
gets a new version number, and readers keep reading version 2.
