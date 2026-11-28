package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// PassphraseFormat is the version of passphrase documents this package
	// writes and reads.
	PassphraseFormat = 2
	// PassphraseKDF names the key derivation of passphrase documents.
	PassphraseKDF = "argon2id"

	// passphrasePasses, passphraseMemoryKiB, and passphraseLanes are the
	// Argon2id parameters new documents use: 3 passes over 64 MiB on 4 lanes.
	passphrasePasses    = 3
	passphraseMemoryKiB = 64 * 1024
	passphraseLanes     = 4
	passphraseSaltBytes = 16
	// maximumPassphraseMemoryKiB and maximumPassphrasePasses bound what a
	// document may ask for, so a damaged or hostile one cannot exhaust
	// memory or time during recovery.
	maximumPassphraseMemoryKiB = 256 << 10
	maximumPassphrasePasses    = 16
	// maximumDocumentBytes, maximumContextBytes, and maximumKEKIDBytes bound
	// a document before anything in it is derived or decrypted.
	maximumDocumentBytes = 16 << 10
	maximumContextBytes  = 1 << 10
	maximumKEKIDBytes    = 255
)

// ErrWrongPassphrase reports a passphrase that does not open a document, or a
// document that was changed.
var ErrWrongPassphrase = errors.New("wrong passphrase, or the passphrase document was changed")

// PassphraseDocument is a KEK wrapped with a key Argon2id derives from a
// passphrase, so a KEK can be recovered with only the document and the
// passphrase. It marshals to JSON. Every field but Created is bound into the
// ciphertext, so changing one makes the document fail to open.
type PassphraseDocument struct {
	// Format is the document version, PassphraseFormat.
	Format int `json:"format"`
	// KDF names the key derivation, PassphraseKDF.
	KDF string `json:"kdf"`
	// Passes is the Argon2id passes over memory.
	Passes uint32 `json:"passes"`
	// MemoryKiB is the Argon2id memory, in KiB.
	MemoryKiB uint32 `json:"memory_kib"`
	// Lanes is the Argon2id parallelism.
	Lanes uint8 `json:"lanes"`
	// Salt is the random Argon2id salt, 16 bytes.
	Salt []byte `json:"salt"`
	// Nonce is the AES-256-GCM nonce the KEK was sealed with, 12 bytes.
	Nonce []byte `json:"nonce"`
	// Wrapped is the sealed KEK and its tag.
	Wrapped []byte `json:"wrapped"`
	// Context names what the KEK belongs to, such as an installation ID.
	Context string `json:"context"`
	// KEKID is the wrapped KEK's ID.
	KEKID string `json:"kek_id"`
	// Created is when the document was written, in UTC. It is not bound
	// into the ciphertext.
	Created time.Time `json:"created"`
}

// WrapWithPassphraseArgs configures Format.WrapWithPassphrase.
type WrapWithPassphraseArgs struct {
	// KEK is the KeyBytes key to wrap. Required.
	KEK []byte
	// KEKID is the KEK's ID, such as LocalKEK.ID. Required.
	KEKID string
	// Passphrase derives the wrapping key. Required; a minimum length or
	// strength is the caller's policy.
	Passphrase string
	// Context names what the KEK belongs to, such as an installation ID.
	Context string
	// Created is recorded in the document.
	Created time.Time
}

// WrapWithPassphrase wraps args.KEK with a key Argon2id derives from
// args.Passphrase and a random salt.
func (f Format) WrapWithPassphrase(args *WrapWithPassphraseArgs) (*PassphraseDocument, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	switch {
	case args == nil:
		return nil, errors.New("no passphrase wrapping arguments")
	case len(args.KEK) != KeyBytes:
		return nil, fmt.Errorf("the KEK must be %d bytes", KeyBytes)
	case args.KEKID == "":
		return nil, errors.New("no KEK ID")
	case args.Passphrase == "":
		return nil, errors.New("no passphrase")
	case len(args.KEKID) > maximumKEKIDBytes || len(args.Context) > maximumContextBytes:
		return nil, fmt.Errorf(
			"a KEK ID is at most %d bytes and a context %d",
			maximumKEKIDBytes,
			maximumContextBytes,
		)
	}
	document := &PassphraseDocument{
		Format:    PassphraseFormat,
		KDF:       PassphraseKDF,
		Passes:    passphrasePasses,
		MemoryKiB: passphraseMemoryKiB,
		Lanes:     passphraseLanes,
		Salt:      make([]byte, passphraseSaltBytes),
		Nonce:     make([]byte, nonceBytes),
		Context:   args.Context,
		KEKID:     args.KEKID,
		Created:   args.Created.UTC(),
	}
	if _, err := rand.Read(document.Salt); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	if _, err := rand.Read(document.Nonce); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	aead, err := document.passphraseAEAD(args.Passphrase)
	if err != nil {
		return nil, err
	}
	document.Wrapped = aead.Seal(
		nil,
		document.Nonce,
		args.KEK,
		f.passphraseAssociatedData(document),
	)
	return document, nil
}

// UnwrapWithPassphrase returns the KEK document holds. A wrong passphrase or a
// changed document is ErrWrongPassphrase. Sizes are checked before any key is
// derived, and the derivation is bounded to 256 MiB and 16 passes, four and
// five times what new documents use, so a hostile document costs seconds.
func (f Format) UnwrapWithPassphrase(
	document *PassphraseDocument,
	passphrase string,
) ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	switch {
	case document == nil:
		return nil, errors.New("no passphrase document")
	case document.Format != PassphraseFormat:
		return nil, fmt.Errorf(
			"%w: passphrase document format %d",
			ErrUnsupportedVersion,
			document.Format,
		)
	case document.KDF != PassphraseKDF:
		return nil, fmt.Errorf("unknown key derivation %q", document.KDF)
	case document.Passes == 0 || document.Passes > maximumPassphrasePasses ||
		document.MemoryKiB == 0 || document.MemoryKiB > maximumPassphraseMemoryKiB ||
		document.Lanes == 0:
		return nil, errors.New("the passphrase document's Argon2id parameters are out of range")
	case len(document.Salt) != passphraseSaltBytes || len(document.Nonce) != nonceBytes ||
		len(document.Wrapped) != KeyBytes+tagBytes ||
		len(document.KEKID) > maximumKEKIDBytes || len(document.Context) > maximumContextBytes:
		return nil, ErrWrongPassphrase
	}
	aead, err := document.passphraseAEAD(passphrase)
	if err != nil {
		return nil, err
	}
	kek, err := aead.Open(
		nil,
		document.Nonce,
		document.Wrapped,
		f.passphraseAssociatedData(document),
	)
	if err != nil || len(kek) != KeyBytes {
		return nil, ErrWrongPassphrase
	}
	return kek, nil
}

// ParsePassphraseDocument decodes a passphrase document from JSON of at most
// 16 KiB.
func ParsePassphraseDocument(content []byte) (*PassphraseDocument, error) {
	if len(content) > maximumDocumentBytes {
		return nil, fmt.Errorf("a passphrase document is at most %d bytes", maximumDocumentBytes)
	}
	document := &PassphraseDocument{}
	if err := json.Unmarshal(content, document); err != nil {
		return nil, fmt.Errorf("reading the passphrase document: %w", err)
	}
	return document, nil
}

// passphraseAEAD derives the wrapping key and returns its AES-256-GCM.
func (d *PassphraseDocument) passphraseAEAD(passphrase string) (cipher.AEAD, error) {
	wrapping := argon2.IDKey([]byte(passphrase), d.Salt, d.Passes, d.MemoryKiB, d.Lanes, KeyBytes)
	block, err := aes.NewCipher(wrapping)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// passphraseAssociatedData binds the Format and every field of the document
// but its ciphertext and creation time, each length-prefixed so no two
// documents share an encoding.
func (f Format) passphraseAssociatedData(d *PassphraseDocument) []byte {
	associated := []byte(f.keyDomain() + " passphrase kek")
	appendField := func(field []byte) {
		associated = binary.BigEndian.AppendUint32(associated, uint32(len(field)))
		associated = append(associated, field...)
	}
	appendField(binary.BigEndian.AppendUint32(nil, uint32(d.Format)))
	appendField([]byte(d.KDF))
	appendField(binary.BigEndian.AppendUint32(nil, d.Passes))
	appendField(binary.BigEndian.AppendUint32(nil, d.MemoryKiB))
	appendField([]byte{d.Lanes})
	appendField(d.Salt)
	appendField([]byte(d.Context))
	appendField([]byte(d.KEKID))
	return associated
}
