package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestPassphraseRoundTrip wraps a key with a passphrase, opens it after a
// JSON round trip, and refuses a wrong passphrase, an empty one, a document
// whose bound fields changed, and one opened under another Format.
func TestPassphraseRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{9}, KeyBytes)
	if _, err := testFormat.WrapWithPassphrase(&WrapWithPassphraseArgs{KEK: key, KEKID: "local-1"}); err == nil {
		t.Fatal("an empty passphrase was accepted")
	}
	document, err := testFormat.WrapWithPassphrase(&WrapWithPassphraseArgs{
		KEK:        key,
		KEKID:      "local-1",
		Passphrase: "correct horse battery staple",
		Context:    "installation",
		Created:    time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePassphraseDocument(encoded)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := testFormat.UnwrapWithPassphrase(parsed, "correct horse battery staple")
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := testFormat.UnwrapWithPassphrase(parsed, "correct horse battery stable"); !errors.Is(
		err,
		ErrWrongPassphrase,
	) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	parsed.Context = "another"
	if _, err := testFormat.UnwrapWithPassphrase(parsed, "correct horse battery staple"); !errors.Is(
		err,
		ErrWrongPassphrase,
	) {
		t.Fatalf("a changed context: %v", err)
	}
	parsed.Context = "installation"
	if _, err := (Format{Magic: "TEST", Label: "another application"}).UnwrapWithPassphrase(parsed, "correct horse battery staple"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("another label: %v", err)
	}
	parsed.MemoryKiB = 1 << 30
	if _, err := testFormat.UnwrapWithPassphrase(parsed, "correct horse battery staple"); err == nil {
		t.Fatal("an out-of-range memory cost was accepted")
	}
}
