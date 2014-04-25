package digest

import (
	"bytes"

	"github.com/azhavnerchik/sasl"
)

type challenge struct {
	realms  [][]byte
	nonce   []byte
	qop     [][]byte // auth or auth-int
	charset []byte
	algo    []byte // md5 or md5-sess, Default md5
	stale   []byte // 'TRUE' or 'FALSE'
}

func newChallenge(gen sasl.NonceGenerator) *challenge {
	return &challenge{
		nonce:   sasl.BytesToHex(gen.GetNonce(cnonce_size)),
		algo:    []byte("md5"),
		qop:     [][]byte{[]byte("auth")},
		charset: []byte("utf-8"),
	}
}

func (c *challenge) SetChallengeQOPs(qops ...string) {
	c.qop = make([][]byte, 0)
	for _, qop := range qops {
		if qop == "auth" || qop == "auth-int" {
			c.qop = append(c.qop, []byte(qop))
		}
	}
}

func (c *challenge) Realms() []string {
	realms := make([]string, len(c.realms))
	for _, realm := range c.realms {
		realms = append(realms, string(realm))
	}
	return realms
}

func (c *challenge) QOPs() []string {
	qops := make([]string, len(c.qop))
	for _, qop := range c.qop {
		qops = append(qops, string(qop))
	}
	return qops
}

func (c *challenge) SetChallengeRealms(srealms ...string) {
	realms := make([][]byte, len(srealms))
	for i, realm := range srealms {
		realms[i] = []byte(realm)
	}
	c.realms = realms
}

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

func (c *challenge) Challenge() []byte {
	challenge := [][]byte{makeKV("nonce", c.nonce), sasl.MakeKeyValue([]byte("algorithm"), c.algo)}
	for _, realm := range c.realms {
		challenge = appendKVQuoted(challenge, "realm", realm)
	}
	challenge = appendKVQuoted(challenge, "qop", sasl.MakeMessage(c.qop...))
	challenge = appendKVQuoted(challenge, "stale", c.stale)
	challenge = appendKV(challenge, "charset", c.charset)

	return sasl.MakeMessage(challenge...)
}

func (c *challenge) ParseChallenge(challenge []byte) error {
	fmap := newFieldMapper()
	fmap.Add("algorithm", &(c.algo))
	fmap.Add("charset", &(c.charset))
	fmap.Add("nonce", &(c.nonce))
	fmap.Add("stale", &(c.stale))

	return sasl.EachField(challenge, func(field []byte) error {
		key, val := sasl.ExtractKeyValue(field, '=')

		val = bytes.Trim(val, "\"")
		switch string(key) {
		case "realm":
			c.realms = bytes.Fields(val)
		case "qop":
			c.qop = bytes.Fields(val)
		default:
			if err := fmap.Set(string(key), val); err != nil {
				return err
			}
		}
		return nil
	})
}
