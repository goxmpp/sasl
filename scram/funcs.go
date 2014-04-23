package scram

import (
	"bytes"
	"encoding/base64"
)

// Extracts proof from Server First message and Base64 decodes it.
// Doens't do any checks except checks that there is at least one
// proof, not more than one proof and proof is Base64-encoded
func ExtractProof(mess []byte) ([]byte, error) {
	b64proof, err := extractParameter(mess, 'p')
	if err != nil {
		return []byte{}, err
	}

	return base64.StdEncoding.DecodeString(string(b64proof))
}

func extractParameter(source []byte, param byte) ([]byte, error) {
	var pvalue []byte
	err := eachToken(source, ',', func(token []byte) error {
		k, v := extractKeyValue(token, '=')

		if k[0] == param {
			if len(pvalue) != 0 {
				return WrongClientMessage("More then one instance of parameter provided")
			}
			pvalue = v
		}
		return nil
	})

	if err != nil {
		return []byte{}, err
	}

	if len(pvalue) == 0 {
		return []byte{}, WrongClientMessage("Parameter not found")
	}

	return pvalue, nil
}

func makeCopy(src []byte) []byte {
	result := make([]byte, len(src))
	copy(result, src)
	return result
}

func makeKeyValue(key byte, value []byte) []byte {
	return append([]byte{key, '='}, value...)
}

func makeScramMessage(kvs ...[]byte) []byte {
	return bytes.Join(kvs, []byte{','})
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
	if mess[0] != 'y' && mess[0] != 'n' && mess[0] != 'p' {
		return WrongClientMessage("Wrong start byte")
	}
	return nil
}

func extractKeyValue(token []byte, sep byte) ([]byte, []byte) {
	kv := bytes.SplitN(token, []byte{sep}, 2)
	return kv[0], kv[1]
}

func saslDePrep(username []byte) []byte {
	return bytes.Replace(
		bytes.Replace(username, []byte{'=', '3', 'D'}, []byte{'='}, -1),
		[]byte{'=', '2', 'C'}, []byte{','}, -1,
	)
}

func saslPrepare(username string) []byte {
	un := []byte(username)
	return bytes.Replace(
		bytes.Replace(un, []byte{'='}, []byte{'=', '3', 'D'}, -1),
		[]byte{','}, []byte{'=', '2', 'C'}, -1,
	)
}

func base64ToBytes(src []byte) []byte {
	dest := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dest, src)
	return dest
}

func byteXOR(left, right []byte) []byte {
	res := make([]byte, len(left))
	for i := range left {
		res[i] = left[i] ^ right[i]
	}
	return res
}
