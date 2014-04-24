package util

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func ExtractParameter(source []byte, param []byte) ([]byte, error) {
	var pvalue []byte
	err := EachToken(source, ',', func(token []byte) error {
		k, v := ExtractKeyValue(token, '=')

		if bytes.Equal(k, param) {
			if len(pvalue) != 0 {
				return fmt.Errorf("More then one instance of parameter '%s' provided", param)
			}
			pvalue = v
		}
		return nil
	})

	if err != nil {
		return []byte{}, err
	}

	if len(pvalue) == 0 {
		return []byte{}, fmt.Errorf("Parameter '%s' not found", param)
	}

	return pvalue, nil
}

func MakeCopy(src []byte) []byte {
	result := make([]byte, len(src))
	copy(result, src)
	return result
}

func MakeKeyValue(key []byte, value []byte) []byte {
	return append(append(key, '='), value...)
}

func MakeMessage(kvs ...[]byte) []byte {
	return bytes.Join(kvs, []byte{','})
}

func EachToken(mess []byte, sep byte, predicate func(token []byte) error) error {
	for _, token := range bytes.Split(mess, []byte{sep}) {
		if err := predicate(token); err != nil {
			return err
		}
	}

	return nil
}
func ExtractKeyValue(token []byte, sep byte) ([]byte, []byte) {
	kv := bytes.SplitN(token, []byte{sep}, 2)
	return kv[0], kv[1]
}

func Base64ToBytes(src []byte) []byte {
	dest := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dest, src)
	return dest
}
