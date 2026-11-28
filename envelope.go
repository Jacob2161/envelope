// Package envelope encrypts objects with AES-256-GCM in 1 MiB frames, so a
// reader can stream an object of any size, and wraps the data keys that
// encrypt them with a key-encryption key (KEK) or a passphrase.
//
//	object = magic[4] u16 version u16 key_id_length key_id salt[32] frame*
//	frame  = u32 ciphertext_length ciphertext
//
// Every object has its own AES key, HKDF-SHA256(data key, salt, label+"
// object v2"), so nonces never repeat across objects however many share one
// data key. Frame i uses nonce u32(0) || u64(i) and authenticates the object
// header, i, and whether it is the final frame, so reordering, splicing, and
// truncation all fail to decrypt. The final frame may be empty, and nothing
// may follow it.
//
// A Format names an application's objects: its magic and the label that
// separates its keys from every other application's. Objects, KEKs, and
// passphrase documents written with one Format open only with the same one.
package envelope

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// FormatVersion is the object format this package writes and reads.
	FormatVersion = 2
	// FrameBytes is the plaintext size of every frame but the last.
	FrameBytes = 1 << 20
	// KeyBytes is the AES-256 key size of data keys and KEKs.
	KeyBytes = 32
	// WrappedKeyBytes is the size of a data key LocalKEK.Wrap sealed: its
	// 12-byte GCM nonce, the key, and the tag.
	WrappedKeyBytes = nonceBytes + KeyBytes + tagBytes
	// SaltBytes is the size of the per-object salt in the header.
	SaltBytes = 32
	// MaximumKeyIDBytes is the longest data key ID a header holds.
	MaximumKeyIDBytes = 255
	// MaximumFrames is the most frames one object holds, the final one
	// included, so no frame index, and so no nonce, repeats: an object holds
	// at most about 4 PiB.
	MaximumFrames = 1 << 32

	nonceBytes  = 12
	tagBytes    = 16
	prefixBytes = 8 // magic, version, key ID length
)

var (
	// ErrDecrypt reports an object or wrapped key that fails authentication,
	// or is damaged or truncated.
	ErrDecrypt = errors.New("object failed authentication")
	// ErrUnknownKey is for a KeyLookup to return when it does not know a key
	// ID; NewReader returns the lookup's error as it is.
	ErrUnknownKey = errors.New("unknown data key")
	// ErrUnsupportedVersion reports a format version this package does not
	// read. It says nothing about damage: a newer writer may have made it.
	ErrUnsupportedVersion = errors.New("unsupported format version")
	// ErrTooLarge refuses plaintext past MaximumFrames frames.
	ErrTooLarge = errors.New("object too large for one envelope")
)

// Format names an application's encrypted objects.
type Format struct {
	// Magic is the four bytes that open every object, such as "APPE".
	Magic string
	// Label separates the application's keys from every other's. It is
	// bound into every derived key and every wrapped key, so changing it
	// makes everything written before unreadable.
	Label string
}

// validate reports a Format that cannot be used.
func (f Format) validate() error {
	if len(f.Magic) != 4 {
		return fmt.Errorf("magic %q is not 4 bytes", f.Magic)
	}
	if f.Label == "" {
		return errors.New("no label")
	}
	return nil
}

// objectKeyInfo is the HKDF info string of per-object keys. The magic is
// bound through the header, which every frame authenticates.
func (f Format) objectKeyInfo() string { return f.Label + " object v2" }

// keyDomain separates the keys a Format wraps from every other Format's,
// magic and label both.
func (f Format) keyDomain() string { return f.Magic + " " + f.Label }

// KeyLookup returns the plaintext data key for an ID found in an object header.
type KeyLookup func(keyID string) ([]byte, error)

// Writer encrypts a stream of plaintext into an envelope object. Close it to
// seal the final frame; until then the object is incomplete and will not
// decrypt.
type Writer struct {
	destination io.Writer
	aead        cipher.AEAD
	header      []byte
	// pending is the plaintext of the frame being filled.
	pending []byte
	// sealed holds a frame's length prefix and ciphertext, reused.
	sealed []byte
	// associatedData is the header followed by the frame index and the
	// final flag, reused for every frame.
	associatedData []byte
	nonce          [nonceBytes]byte
	frame          uint32
	closed         bool
	err            error
}

// NewWriter writes an object header for keyID to destination and returns a
// writer for the plaintext. dataKey must be KeyBytes long.
func (f Format) NewWriter(destination io.Writer, keyID string, dataKey []byte) (*Writer, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	if len(keyID) == 0 || len(keyID) > MaximumKeyIDBytes {
		return nil, fmt.Errorf("key ID must be 1 to %d bytes", MaximumKeyIDBytes)
	}
	salt := make([]byte, SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	aead, err := objectAEAD(f, dataKey, salt)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, prefixBytes+len(keyID)+SaltBytes)
	header = append(header, f.Magic...)
	header = binary.BigEndian.AppendUint16(header, FormatVersion)
	header = binary.BigEndian.AppendUint16(header, uint16(len(keyID)))
	header = append(header, keyID...)
	header = append(header, salt...)
	if _, err := destination.Write(header); err != nil {
		return nil, fmt.Errorf("writing the header: %w", err)
	}
	return &Writer{
		destination:    destination,
		aead:           aead,
		header:         header,
		pending:        make([]byte, 0, FrameBytes),
		sealed:         make([]byte, 0, 4+FrameBytes+tagBytes),
		associatedData: append(make([]byte, 0, len(header)+5), header...),
	}, nil
}

// objectAEAD derives one object's key from its data key and salt.
func objectAEAD(format Format, dataKey []byte, salt []byte) (cipher.AEAD, error) {
	if len(dataKey) != KeyBytes {
		return nil, fmt.Errorf("data key must be %d bytes", KeyBytes)
	}
	objectKey, err := hkdf.Key(sha256.New, dataKey, salt, format.objectKeyInfo(), KeyBytes)
	if err != nil {
		return nil, fmt.Errorf("deriving the object key: %w", err)
	}
	return newAEAD(objectKey)
}

// newAEAD builds AES-256-GCM for a 32-byte key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("key must be %d bytes", KeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Write buffers plaintext and seals each full frame. After a failed write
// every later Write and Close returns the same error.
func (w *Writer) Write(plaintext []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("write after close")
	}
	written := 0
	for len(plaintext) > 0 {
		chunk := min(FrameBytes-len(w.pending), len(plaintext))
		w.pending = append(w.pending, plaintext[:chunk]...)
		plaintext = plaintext[chunk:]
		written += chunk
		if len(w.pending) == FrameBytes {
			// The last index is the final frame's, sealed by Close.
			if w.frame == MaximumFrames-1 {
				w.err = ErrTooLarge
				return written - chunk, w.err
			}
			if err := w.sealFrame(false); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// Close seals the final frame. It does not close the destination. Closing
// twice does nothing.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}
	w.closed = true
	return w.sealFrame(true)
}

// sealFrame encrypts the pending plaintext as frame w.frame and writes it,
// length prefix and ciphertext together.
func (w *Writer) sealFrame(final bool) error {
	putFrameNonce(&w.nonce, w.frame)
	w.associatedData = appendFrameContext(w.associatedData[:len(w.header)], w.frame, final)
	w.sealed = binary.BigEndian.AppendUint32(w.sealed[:0], uint32(len(w.pending)+tagBytes))
	w.sealed = w.aead.Seal(w.sealed, w.nonce[:], w.pending, w.associatedData)
	if _, err := w.destination.Write(w.sealed); err != nil {
		w.err = fmt.Errorf("writing frame %d: %w", w.frame, err)
		return w.err
	}
	w.frame++
	w.pending = w.pending[:0]
	return nil
}

// putFrameNonce sets nonce to four zero bytes followed by the 64-bit frame
// index. The key is unique to the object, so a counter is enough.
func putFrameNonce(nonce *[nonceBytes]byte, frame uint32) {
	binary.BigEndian.PutUint64(nonce[4:], uint64(frame))
}

// appendFrameContext appends what binds a frame to its position and
// finality to the header in associated.
func appendFrameContext(associated []byte, frame uint32, final bool) []byte {
	associated = binary.BigEndian.AppendUint32(associated, frame)
	if final {
		return append(associated, 1)
	}
	return append(associated, 0)
}

// Reader decrypts an envelope object, failing on any tampering, truncation,
// or bytes after the final frame.
type Reader struct {
	source         *bufio.Reader
	aead           cipher.AEAD
	header         []byte
	keyID          string
	associatedData []byte
	nonce          [nonceBytes]byte
	// sealed holds the current frame's ciphertext and plainBuffer its
	// plaintext, both reused; plain is the part of it not yet read.
	sealed      []byte
	plainBuffer []byte
	plain       []byte
	frame       uint32
	done        bool
	err         error
}

// NewReader reads an object header from source, resolves its data key with
// lookup, and returns a reader for the plaintext. A lookup error is returned
// as it is.
func (f Format) NewReader(source io.Reader, lookup KeyLookup) (*Reader, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	buffered := bufio.NewReaderSize(sourceReader{source: source}, 64<<10)
	prefix := make([]byte, prefixBytes, prefixBytes+MaximumKeyIDBytes+SaltBytes)
	if _, err := io.ReadFull(buffered, prefix); err != nil {
		return nil, readFailure(err, "the header")
	}
	if string(prefix[:4]) != f.Magic {
		return nil, fmt.Errorf("%w: not an object of this format", ErrDecrypt)
	}
	formatVersion := binary.BigEndian.Uint16(prefix[4:6])
	if formatVersion != FormatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, formatVersion)
	}
	keyIDLength := int(binary.BigEndian.Uint16(prefix[6:8]))
	if keyIDLength == 0 || keyIDLength > MaximumKeyIDBytes {
		return nil, fmt.Errorf("%w: key ID length %d", ErrDecrypt, keyIDLength)
	}
	header := prefix[:prefixBytes+keyIDLength+SaltBytes]
	if _, err := io.ReadFull(buffered, header[prefixBytes:]); err != nil {
		return nil, readFailure(err, "the header")
	}
	keyID := string(header[prefixBytes : prefixBytes+keyIDLength])
	dataKey, err := lookup(keyID)
	if err != nil {
		return nil, err
	}
	aead, err := objectAEAD(f, dataKey, header[prefixBytes+keyIDLength:])
	if err != nil {
		return nil, err
	}
	return &Reader{
		source:         buffered,
		aead:           aead,
		header:         header,
		keyID:          keyID,
		associatedData: append(make([]byte, 0, len(header)+5), header...),
	}, nil
}

// KeyID is the data key ID the object's header names.
func (r *Reader) KeyID() string { return r.keyID }

// Read returns decrypted plaintext. A damaged or truncated object fails with
// an error wrapping ErrDecrypt; a source that fails to read fails with its
// own error, which does not wrap ErrDecrypt, since it says nothing about the
// object. Every later Read returns the same error.
func (r *Reader) Read(target []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.openFrame(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(target, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

// openFrame reads and authenticates the next frame. A frame shorter than full
// size must be final; a full frame is tried as non-final first. After the
// final frame the source must end. The ciphertext and plaintext buffers are
// separate and reused: a failed Open may overwrite its destination, and the
// ciphertext must survive a failed non-final attempt.
func (r *Reader) openFrame() error {
	var prefix [4]byte
	if _, err := io.ReadFull(r.source, prefix[:]); err != nil {
		return readFailure(err, fmt.Sprintf("frame %d", r.frame))
	}
	length := int(binary.BigEndian.Uint32(prefix[:]))
	if length < tagBytes || length > FrameBytes+tagBytes {
		return fmt.Errorf("%w: frame %d length %d", ErrDecrypt, r.frame, length)
	}
	if r.sealed == nil {
		r.sealed = make([]byte, FrameBytes+tagBytes)
		r.plainBuffer = make([]byte, 0, FrameBytes)
	}
	sealed := r.sealed[:length]
	if _, err := io.ReadFull(r.source, sealed); err != nil {
		return readFailure(err, fmt.Sprintf("frame %d", r.frame))
	}
	putFrameNonce(&r.nonce, r.frame)
	// The last index can only be the final frame's.
	if length == FrameBytes+tagBytes && r.frame < MaximumFrames-1 {
		r.associatedData = appendFrameContext(
			r.associatedData[:len(r.header)],
			r.frame,
			false,
		)
		plain, err := r.aead.Open(r.plainBuffer[:0], r.nonce[:], sealed, r.associatedData)
		if err == nil {
			r.plain = plain
			r.frame++
			return nil
		}
	}
	r.associatedData = appendFrameContext(r.associatedData[:len(r.header)], r.frame, true)
	plain, err := r.aead.Open(r.plainBuffer[:0], r.nonce[:], sealed, r.associatedData)
	if err != nil {
		return fmt.Errorf("%w: frame %d", ErrDecrypt, r.frame)
	}
	return r.finish(plain)
}

// finish keeps the final frame's plaintext and checks that nothing follows it.
func (r *Reader) finish(plain []byte) error {
	_, err := r.source.Peek(1)
	if err == nil {
		return fmt.Errorf("%w: data after the final frame", ErrDecrypt)
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading after the final frame: %w", err)
	}
	r.plain = plain
	r.frame++
	r.done = true
	return nil
}

// readFailure is the error for a read of part (the header, or a frame) that
// did not complete: ErrDecrypt when the object ended early, since a
// truncated object is damaged, and otherwise the source's own error, which
// says nothing about the object.
func readFailure(err error, part string) error {
	failed, fromSource := errors.AsType[*sourceError](err)
	if fromSource {
		return fmt.Errorf("reading %s: %w", part, failed.err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %s is truncated", ErrDecrypt, part)
	}
	return fmt.Errorf("reading %s: %w", part, err)
}

// sourceReader marks every error of the source but its end as the
// source's, so a transport that fails with io.ErrUnexpectedEOF, as a
// truncated HTTP body does, is not taken for an object that ended early.
type sourceReader struct {
	source io.Reader
}

// Read reads from the source, wrapping a failure in sourceError.
func (r sourceReader) Read(buffer []byte) (int, error) {
	read, err := r.source.Read(buffer)
	if err != nil && err != io.EOF {
		err = &sourceError{err: err}
	}
	return read, err
}

// sourceError is a failure of the source itself, not of the object.
type sourceError struct {
	err error
}

// Error returns the source's error text.
func (e *sourceError) Error() string { return e.err.Error() }

// Unwrap returns the source's error.
func (e *sourceError) Unwrap() error { return e.err }

// KeyWrapper wraps data keys with a KEK. LocalKEK implements it; a KMS or
// Vault Transit client can too, so a caller that stores wrapped keys holds a
// KeyWrapper rather than a *LocalKEK.
type KeyWrapper interface {
	// ID identifies the KEK without revealing it.
	ID() string
	// Wrap seals a data key so only this KEK can open it.
	Wrap(dataKey []byte) ([]byte, error)
	// Unwrap opens a data key Wrap sealed. A key another KEK wrapped, or a
	// damaged one, is ErrDecrypt.
	Unwrap(wrapped []byte) ([]byte, error)
}

// LocalKEK is a KEK held in memory: a 32-byte key an operator provides or the
// application generates.
type LocalKEK struct {
	aead cipher.AEAD
	id   string
}

// NewLocalKEK returns a KeyWrapper for a 32-byte key. Its ID is derived from
// the key and the Format, so another Format's KEK over the same key has
// another ID and cannot open what this one wrapped.
func (f Format) NewLocalKEK(key []byte) (*LocalKEK, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(f.keyDomain()+" kek id "), key...))
	return &LocalKEK{aead: aead, id: "local-" + hex.EncodeToString(sum[:8])}, nil
}

// ID identifies the KEK without revealing it.
func (k *LocalKEK) ID() string { return k.id }

// Wrap seals a data key as nonce || ciphertext, bound to the KEK's ID.
func (k *LocalKEK) Wrap(dataKey []byte) ([]byte, error) {
	nonce := make([]byte, nonceBytes, nonceBytes+len(dataKey)+tagBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return k.aead.Seal(nonce, nonce, dataKey, []byte(k.id)), nil
}

// Unwrap opens a wrapped data key. A key wrapped by another KEK, or damaged,
// is ErrDecrypt.
func (k *LocalKEK) Unwrap(wrapped []byte) ([]byte, error) {
	if len(wrapped) < nonceBytes+tagBytes {
		return nil, ErrDecrypt
	}
	plain, err := k.aead.Open(nil, wrapped[:nonceBytes], wrapped[nonceBytes:], []byte(k.id))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// NewDataKey returns a random 32-byte data key.
func NewDataKey() ([]byte, error) {
	key := make([]byte, KeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return key, nil
}
