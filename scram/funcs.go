package scram

import (
	"bytes"
	"encoding/base64"
)

func ExtractProof(mess []byte) ([]byte, error) {
	var b64proof []byte
	err := eachToken(mess, ',', func(token []byte) error {
		k, v := extractKeyValue(token, '=')

		if k[0] == 'p' {
			if len(b64proof) != 0 {
				return WrongClientMessage("More then one proof provided")
			}
			b64proof = v
		}
		return nil
	})

	if err != nil {
		return []byte{}, err
	}

	if len(b64proof) == 0 {
		return []byte{}, WrongClientMessage("Proof not found")
	}

	proof := make([]byte, base64.StdEncoding.DecodedLen(len(b64proof)))
	if _, err := base64.StdEncoding.Decode(proof, b64proof); err != nil {
		return []byte{}, nil
	}

	return proof, nil
}

func eachToken(mess []byte, sep byte, predicate func(token []byte) error) error {
	for _, token := range bytes.Split(mess, []byte{sep}) {
		if err := predicate(token); err != nil {
			return err
		}
	}

	return nil
}

func validateMessage(mess []byte) error {
	if !bytes.HasPrefix(mess, []byte{'y', 'n', 'p'}) {
		return WrongClientMessage("Wrong start byte")
	}
	return nil
}

func extractKeyValue(token []byte, sep byte) ([]byte, []byte) {
	kv := bytes.SplitN(token, []byte{sep}, 2)
	return kv[0], kv[1]
}

func saslDePrep(username []byte) string {
	// TODO implement real logic
	return string(username)
}

func saslPrepare(username string) string {
	//panic("Not implemented")
	return username
}

func byteXOR(left, right []byte) []byte {
	res := make([]byte, len(left))
	for i := range left {
		res[i] = left[i] ^ right[i]
	}
	return res
}
