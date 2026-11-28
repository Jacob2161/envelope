package envelope

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// testFormat is the Format of the tests' own objects.
var testFormat = Format{Magic: "TEST", Label: "envelope test"}

// encrypt seals plaintext with a fixed test key.
func encrypt(t *testing.T, key []byte, plaintext []byte) []byte {
	t.Helper()
	var object bytes.Buffer
	writer, err := testFormat.NewWriter(&object, "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return object.Bytes()
}

// decrypt opens an object with the test key.
func decrypt(key []byte, object []byte) ([]byte, error) {
	reader, err := testFormat.NewReader(
		bytes.NewReader(object),
		func(keyID string) ([]byte, error) {
			if keyID != "key-1" {
				return nil, ErrUnknownKey
			}
			return key, nil
		},
	)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

// TestRoundTripAndTampering covers frame boundaries, truncation, and bit flips.
func TestRoundTripAndTampering(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{
		0,
		1,
		FrameBytes - 1,
		FrameBytes,
		FrameBytes + 1,
		3*FrameBytes + 17,
	} {
		plaintext := bytes.Repeat([]byte{byte(size)}, size)
		object := encrypt(t, key, plaintext)
		opened, err := decrypt(key, object)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("size %d: plaintext differs", size)
		}
		if size >= FrameBytes {
			// Dropping the final frame must not look like a shorter valid object.
			truncated := object[:len(object)-(4+tagBytes+size%FrameBytes)]
			if _, err := decrypt(key, truncated); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("size %d: truncation not detected: %v", size, err)
			}
		}
		damaged := append([]byte(nil), object...)
		damaged[len(damaged)-1] ^= 1
		if _, err := decrypt(key, damaged); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("size %d: tampering not detected", size)
		}
	}
}

// TestLocalKEK checks wrapping and that a different KEK cannot unwrap.
func TestLocalKEK(t *testing.T) {
	first, err := testFormat.NewLocalKEK(bytes.Repeat([]byte{1}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	second, err := testFormat.NewLocalKEK(bytes.Repeat([]byte{2}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := first.Wrap(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := first.Unwrap(wrapped)
	if err != nil || !bytes.Equal(unwrapped, dataKey) {
		t.Fatal("unwrap failed")
	}
	if _, err := second.Unwrap(wrapped); err == nil {
		t.Fatal("a different KEK unwrapped the key")
	}
	if first.ID() == second.ID() {
		t.Fatal("KEK IDs collide")
	}
}

// TestSpliceAndSalt checks that objects under one data key get their own
// keys: a frame moved from one object to another at the same index fails,
// as does a changed salt, while each object opens alone.
func TestSpliceAndSalt(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte{9}, 2*FrameBytes+5)
	first := encrypt(t, key, plaintext)
	second := encrypt(t, key, plaintext)
	headerBytes := 8 + len("key-1") + SaltBytes
	if bytes.Equal(first[headerBytes:], second[headerBytes:]) {
		t.Fatal("two objects under one data key share ciphertext")
	}
	frameBytes := 4 + FrameBytes + tagBytes
	// Copy the first frame of second over first's: same index, same data key.
	spliced := append([]byte(nil), first...)
	copy(spliced[headerBytes:headerBytes+frameBytes], second[headerBytes:headerBytes+frameBytes])
	if _, err := decrypt(key, spliced); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a frame spliced from another object opened: %v", err)
	}
	// Reordering frames within one object fails.
	reordered := append([]byte(nil), first...)
	copy(reordered[headerBytes:], first[headerBytes+frameBytes:headerBytes+2*frameBytes])
	copy(reordered[headerBytes+frameBytes:], first[headerBytes:headerBytes+frameBytes])
	if _, err := decrypt(key, reordered); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("reordered frames opened: %v", err)
	}
	salted := append([]byte(nil), first...)
	salted[headerBytes-1] ^= 1
	if _, err := decrypt(key, salted); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a changed salt opened: %v", err)
	}
	for _, object := range [][]byte{first, second} {
		opened, err := decrypt(key, object)
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("object did not open: %v", err)
		}
	}
}

// TestUnsupportedVersion checks that another envelope version is reported
// as unsupported, never as damage.
func TestUnsupportedVersion(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	object := encrypt(t, key, []byte("hello"))
	object[5] = FormatVersion + 1
	_, err = decrypt(key, object)
	if !errors.Is(err, ErrUnsupportedVersion) || errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v", err)
	}
}

// TestFormatSeparation checks that objects and KEKs of one Format do not open
// under another, and that unusable Formats are refused.
func TestFormatSeparation(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	object := encrypt(t, key, []byte("hello"))
	sameMagic := Format{Magic: testFormat.Magic, Label: "another application"}
	lookup := func(string) ([]byte, error) { return key, nil }
	reader, err := sameMagic.NewReader(bytes.NewReader(object), lookup)
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("an object opened under another label: %v", err)
	}
	foreignMagicFormat := Format{Magic: "OTHR", Label: testFormat.Label}
	_, err = foreignMagicFormat.NewReader(bytes.NewReader(object), lookup)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("an object opened under another magic: %v", err)
	}
	first, err := testFormat.NewLocalKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sameMagic.NewLocalKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := first.Wrap(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Unwrap(wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a key wrapped under one label unwrapped under another: %v", err)
	}
	foreignMagic, err := (Format{Magic: "OTHR", Label: testFormat.Label}).NewLocalKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	if foreignMagic.ID() == first.ID() {
		t.Fatal("two Formats with one label share KEK IDs")
	}
	if _, err := foreignMagic.Unwrap(wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a key wrapped under one magic unwrapped under another: %v", err)
	}
	for _, format := range []Format{{Magic: "ABC", Label: "x"}, {Magic: "ABCD"}} {
		if _, err := format.NewWriter(io.Discard, "key-1", key); err == nil {
			t.Errorf("format %+v was accepted", format)
		}
	}
}

// TestTrailingDataIsRefused checks that bytes after the final frame fail.
func TestTrailingDataIsRefused(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	object := append(encrypt(t, key, []byte("hello")), 0)
	if _, err := decrypt(key, object); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("an object with trailing data opened: %v", err)
	}
}

// failingWriter fails every write after the first n.
type failingWriter struct{ remaining int }

func (w *failingWriter) Write(content []byte) (int, error) {
	if w.remaining == 0 {
		return 0, errors.New("disk full")
	}
	w.remaining--
	return len(content), nil
}

// TestWriterKeepsItsError checks that a failed frame write fails every later
// Write and Close.
func TestWriterKeepsItsError(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	writer, err := testFormat.NewWriter(&failingWriter{remaining: 1}, "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(make([]byte, FrameBytes)); err == nil {
		t.Fatal("a failed frame write succeeded")
	}
	if _, err := writer.Write([]byte("more")); err == nil {
		t.Fatal("a write after a failure succeeded")
	}
	if err := writer.Close(); err == nil {
		t.Fatal("a close after a failure succeeded")
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	key := bytes.Repeat([]byte{1}, KeyBytes)
	plaintext := bytes.Repeat([]byte("x"), 16<<20)
	lookup := func(string) ([]byte, error) { return key, nil }
	var object bytes.Buffer
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	for b.Loop() {
		object.Reset()
		writer, err := testFormat.NewWriter(&object, "key-1", key)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := writer.Write(plaintext); err != nil {
			b.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			b.Fatal(err)
		}
		reader, err := testFormat.NewReader(&object, lookup)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
	}
}

// TestFrameIndexNeverRepeats checks both ends of the frame counter: a writer
// refuses a full frame at the last index, which only the final frame may
// use, and a reader refuses a non-final frame there.
func TestFrameIndexNeverRepeats(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	var object bytes.Buffer
	writer, err := testFormat.NewWriter(&object, "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	writer.frame = MaximumFrames - 1
	if _, err := writer.Write(make([]byte, FrameBytes)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a full frame at the last index: %v", err)
	}
	if err := writer.Close(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("closing after the refusal: %v", err)
	}

	// Seal a non-final frame at the last index by hand, as a forger would.
	forged, err := testFormat.NewWriter(io.Discard, "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	forged.destination = &sealed
	forged.frame = MaximumFrames - 1
	forged.pending = append(forged.pending[:0], make([]byte, FrameBytes)...)
	if err := forged.sealFrame(false); err != nil {
		t.Fatal(err)
	}
	// The forged frame needs the forger's own header, whose salt keys it.
	forgedObject := append(append([]byte(nil), forged.header...), sealed.Bytes()...)
	reader, err := testFormat.NewReader(
		bytes.NewReader(forgedObject),
		func(string) ([]byte, error) { return key, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	reader.frame = MaximumFrames - 1
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a non-final frame at the last index opened: %v", err)
	}
}

// TestPassphraseDocumentBounds checks that oversized documents and fields are
// refused before any key is derived.
func TestPassphraseDocumentBounds(t *testing.T) {
	if _, err := ParsePassphraseDocument(bytes.Repeat([]byte(" "), 32<<10)); err == nil {
		t.Fatal("a 32 KiB document was parsed")
	}
	document, err := testFormat.WrapWithPassphrase(&WrapWithPassphraseArgs{
		KEK: bytes.Repeat([]byte{1}, KeyBytes), KEKID: "local-1", Passphrase: "a passphrase",
	})
	if err != nil {
		t.Fatal(err)
	}
	oversized := *document
	oversized.Wrapped = make([]byte, 1<<20)
	_, err = testFormat.UnwrapWithPassphrase(&oversized, "a passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("a 1 MiB wrapped key: %v", err)
	}
	if _, err := testFormat.WrapWithPassphrase(&WrapWithPassphraseArgs{
		KEK: bytes.Repeat([]byte{1}, KeyBytes), KEKID: "local-1", Passphrase: "a passphrase",
		Context: string(make([]byte, 2<<10)),
	}); err == nil {
		t.Fatal("a 2 KiB context was accepted")
	}
}

// errConnectionReset stands for a source that fails partway, as a network
// read does.
var errConnectionReset = errors.New("connection reset by peer")

// TestSourceFailureIsNotDamage checks that a source that fails to read, in
// the header or in a frame, fails with its own error and not ErrDecrypt, so
// a caller does not mistake a dropped connection for a damaged object, while
// an object that ends early is still ErrDecrypt.
func TestSourceFailureIsNotDamage(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	object := encrypt(t, key, bytes.Repeat([]byte("x"), FrameBytes+10))
	lookup := func(string) ([]byte, error) { return key, nil }
	for name, cut := range map[string]int{
		"in the header":      3,
		"in the first frame": prefixBytes + len("key-1") + SaltBytes + 100,
	} {
		// io.ErrUnexpectedEOF is what a truncated HTTP body returns when its
		// connection closes before the Content-Length.
		for _, failure := range []error{errConnectionReset, io.ErrUnexpectedEOF} {
			source := io.MultiReader(
				bytes.NewReader(object[:cut]),
				iotest.ErrReader(failure),
			)
			reader, err := testFormat.NewReader(source, lookup)
			if err == nil {
				_, err = io.ReadAll(reader)
			}
			if !errors.Is(err, failure) || errors.Is(err, ErrDecrypt) {
				t.Errorf(
					"a source failing %s with %v: %v, want the source's error alone",
					name,
					failure,
					err,
				)
			}
		}
		_, err = decrypt(key, object[:cut])
		if !errors.Is(err, ErrDecrypt) {
			t.Errorf("an object ending %s: %v, want ErrDecrypt", name, err)
		}
	}
}
