package scram

import (
	"bytes"
	"encoding/base64"

	"github.com/azhavnerchik/sasl"
)

// Extracts proof from Server First message and Base64 decodes it.
// Doens't do any checks except checks that there is at least one
// proof, not more than one proof and proof is Base64-encoded
func extractProof(mess []byte) ([]byte, error) {
	b64proof, err := extractParameter(mess, 'p')
	if err != nil {
		return []byte{}, err
	}

	return base64.StdEncoding.DecodeString(string(b64proof))
}

func extractParameter(mess []byte, param byte) ([]byte, error) {
	return sasl.ExtractParameter(mess, []byte{param})
}

func makeKeyValue(key byte, value []byte) []byte {
	return sasl.MakeKeyValue([]byte{key}, value)
}

func validateMessage(mess []byte) error {
	if mess[0] != 'y' && mess[0] != 'n' && mess[0] != 'p' {
		return WrongClientMessage("Wrong start byte")
	}
	return nil
}

func deprepare(username []byte) []byte {
	return bytes.Replace(
		bytes.Replace(username, []byte{'=', '3', 'D'}, []byte{'='}, -1),
		[]byte{'=', '2', 'C'}, []byte{','}, -1,
	)
}

func prepare(username string) []byte {
	un := []byte(username)
	return bytes.Replace(
		bytes.Replace(un, []byte{'='}, []byte{'=', '3', 'D'}, -1),
		[]byte{','}, []byte{'=', '2', 'C'}, -1,
	)
}

func byteXOR(left, right []byte) []byte {
	res := make([]byte, len(left))
	for i := range left {
		res[i] = left[i] ^ right[i]
	}
	return res
}
