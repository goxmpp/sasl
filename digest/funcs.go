package digest

import (
	"bytes"

	"github.com/azhavnerchik/sasl"
)

func makeKV(key string, val []byte) []byte {
	return sasl.MakeKeyValue([]byte(key), append(append([]byte{'"'}, val...), '"'))
}

func appendKVQuoted(kvs [][]byte, key string, val []byte) [][]byte {
	if len(val) > 0 {
		return append(kvs, makeKV(key, val))
	}
	return kvs
}

func appendKV(kvs [][]byte, key string, val []byte) [][]byte {
	if len(val) > 0 {
		return append(kvs, sasl.MakeKeyValue([]byte(key), val))
	}
	return kvs
}

func makeMessage(tokens ...[]byte) []byte {
	return bytes.Join(tokens, []byte{':'})
}
