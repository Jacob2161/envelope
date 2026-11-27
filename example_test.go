package envelope_test

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/jacob2161/envelope"
)

// objects is an application's Format. Choose the magic and label once and
// never change them: everything written before becomes unreadable.
var objects = envelope.Format{Magic: "EXMP", Label: "example application"}

func Example() {
	// A KEK protects data keys; data keys encrypt objects.
	kek, err := objects.NewLocalKEK(bytes.Repeat([]byte{7}, envelope.KeyBytes))
	if err != nil {
		log.Fatal(err)
	}
	dataKey, err := envelope.NewDataKey()
	if err != nil {
		log.Fatal(err)
	}
	wrappedDataKey, err := kek.Wrap(dataKey) // store this beside the objects
	if err != nil {
		log.Fatal(err)
	}

	var object bytes.Buffer
	writer, err := objects.NewWriter(&object, "data-key-1", dataKey)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.WriteString(writer, "hello, envelope"); err != nil {
		log.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		log.Fatal(err)
	}

	reader, err := objects.NewReader(&object, func(keyID string) ([]byte, error) {
		if keyID != "data-key-1" {
			return nil, envelope.ErrUnknownKey
		}
		return kek.Unwrap(wrappedDataKey)
	})
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext))
	// Output: hello, envelope
}
