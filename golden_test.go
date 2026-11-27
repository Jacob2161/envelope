package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The golden objects and wrapped key are checked in from format version 2 and
// must open unchanged in every later version: applications keep objects and
// data keys for years. Never regenerate them. ENVELOPE_GOLDEN_WRITE=1 writes
// only the files that are missing.

// goldenFormat is the Format the golden files were written with.
var goldenFormat = Format{Magic: "ENVG", Label: "envelope golden"}

// goldenKEK and goldenDataKey are test keys, never used outside this file.
var (
	goldenKEK     = bytes.Repeat([]byte{0x4b}, KeyBytes)
	goldenDataKey = bytes.Repeat([]byte{0x44}, KeyBytes)
)

// goldenKeyID is the data key ID the golden objects name.
const goldenKeyID = "2025-11-0192f3a4"

// goldenObjects maps each golden object to its plaintext.
var goldenObjects = map[string][]byte{
	"v2-empty.envelope": nil,
	"v2-text.envelope":  bytes.Repeat([]byte("golden envelope plaintext\n"), 40),
}

// goldenLookup resolves the golden data key.
func goldenLookup(keyID string) ([]byte, error) {
	if keyID != goldenKeyID {
		return nil, ErrUnknownKey
	}
	return goldenDataKey, nil
}

// writeGoldenFile writes content to testdata/name when it is missing and
// ENVELOPE_GOLDEN_WRITE=1, then returns the checked-in bytes.
func writeGoldenFile(t *testing.T, name string, content func() []byte) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("ENVELOPE_GOLDEN_WRITE") == "1" {
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, content(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	checkedIn, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return checkedIn
}

// TestGoldenEnvelopes opens the checked-in version 2 objects.
func TestGoldenEnvelopes(t *testing.T) {
	for name, plaintext := range goldenObjects {
		object := writeGoldenFile(t, name, func() []byte {
			var object bytes.Buffer
			writer, err := goldenFormat.NewWriter(&object, goldenKeyID, goldenDataKey)
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
		})
		reader, err := goldenFormat.NewReader(bytes.NewReader(object), goldenLookup)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if reader.KeyID() != goldenKeyID {
			t.Fatalf("%s: key ID %q", name, reader.KeyID())
		}
		opened, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("%s: plaintext differs", name)
		}
	}
}

// TestGoldenWrappedKey unwraps the checked-in data key with the golden KEK.
func TestGoldenWrappedKey(t *testing.T) {
	kek, err := goldenFormat.NewLocalKEK(goldenKEK)
	if err != nil {
		t.Fatal(err)
	}
	if kek.ID() != "local-5ee3a9035584660c" {
		t.Fatalf("KEK ID %q changed", kek.ID())
	}
	wrapped := writeGoldenFile(t, "v2-data.key", func() []byte {
		wrapped, err := kek.Wrap(goldenDataKey)
		if err != nil {
			t.Fatal(err)
		}
		return wrapped
	})
	unwrapped, err := kek.Unwrap(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, goldenDataKey) {
		t.Fatal("unwrapped data key differs")
	}
}

// FuzzReader feeds arbitrary bytes to the envelope reader. It must never
// panic, and every failure must be one of the reader's own errors.
func FuzzReader(f *testing.F) {
	for name := range goldenObjects {
		object, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(object)
		f.Add(object[:len(object)-1])
	}
	f.Fuzz(func(t *testing.T, object []byte) {
		reader, err := goldenFormat.NewReader(bytes.NewReader(object), goldenLookup)
		if err == nil {
			_, err = io.ReadAll(reader)
		}
		if err != nil && !errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrUnsupportedVersion) &&
			!errors.Is(err, ErrUnknownKey) {
			t.Fatalf("unexpected error type: %v", err)
		}
	})
}

// FuzzUnwrap feeds arbitrary bytes to the KEK. Only the golden key unwraps.
func FuzzUnwrap(f *testing.F) {
	kek, err := goldenFormat.NewLocalKEK(goldenKEK)
	if err != nil {
		f.Fatal(err)
	}
	wrapped, err := os.ReadFile(filepath.Join("testdata", "v2-data.key"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wrapped)
	f.Fuzz(func(t *testing.T, wrapped []byte) {
		unwrapped, err := kek.Unwrap(wrapped)
		if err != nil {
			if !errors.Is(err, ErrDecrypt) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if !bytes.Equal(unwrapped, goldenDataKey) {
			t.Fatal("a forged wrapping unwrapped")
		}
	})
}

// goldenPassphrase opens the golden passphrase document.
const goldenPassphrase = "golden passphrase for the envelope tests"

// TestGoldenPassphraseDocument opens the checked-in passphrase document,
// which must open unchanged in every later version.
func TestGoldenPassphraseDocument(t *testing.T) {
	content := writeGoldenFile(t, "v2-passphrase.json", func() []byte {
		document, err := goldenFormat.WrapWithPassphrase(&WrapWithPassphraseArgs{
			KEK:        goldenKEK,
			KEKID:      "local-5ee3a9035584660c",
			Passphrase: goldenPassphrase,
			Context:    "golden installation",
			Created:    time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return append(encoded, '\n')
	})
	document, err := ParsePassphraseDocument(content)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := goldenFormat.UnwrapWithPassphrase(document, goldenPassphrase)
	if err != nil || !bytes.Equal(kek, goldenKEK) {
		t.Fatalf("the golden passphrase document did not open: %v", err)
	}
}
