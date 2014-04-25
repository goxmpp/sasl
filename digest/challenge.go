package digest

import (
	"bytes"
	"errors"

	"github.com/azhavnerchik/sasl/generator"
	"github.com/azhavnerchik/sasl/mbytes"
)

type challenge struct {
	realms  [][]byte
	nonce   []byte
	qop     [][]byte // auth or auth-int
	charset []byte
	algo    []byte // md5 or md5-sess, Default md5
	stale   []byte // 'TRUE' or 'FALSE'
}

func newChallenge(gen generator.NonceGenerator) *challenge {
	return &challenge{
		nonce: mbytes.BytesToHex(gen.GetNonce(cnonce_size)),
		algo:  []byte("md5"),
		qop:   [][]byte{[]byte("auth")},
	}
}

func (c *challenge) SetQOP(qops ...string) {
	for _, qop := range qops {
		if qop == "auth" || qop == "auth-int" {
			c.qop = append(c.qop, []byte(qop))
		}
	}
}

func (c *challenge) SetAlgorithm(algo string) error {
	if algo != "MD5" && algo != "MD5-sess" {
		return errors.New("Wrong algorithm specified")
	}

	c.algo = []byte(algo)
	return nil
}

func (c *challenge) SetChallengeRealms(srealms ...string) {
	realms := make([][]byte, len(srealms))
	for i, realm := range srealms {
		realms[i] = []byte(realm)
	}
	c.realms = realms
}

func makeKV(key string, val []byte) []byte {
	return mbytes.MakeKeyValue([]byte(key), append(append([]byte{'"'}, val...), '"'))
}

func appendKV(kvs [][]byte, key string, val []byte) [][]byte {
	if len(val) > 0 {
		return append(kvs, makeKV(key, val))
	}
	return kvs
}

func (c *challenge) Challenge() []byte {
	challenge := [][]byte{makeKV("nonce", c.nonce), makeKV("algorithm", c.algo)}
	challenge = appendKV(challenge, "realm", mbytes.MakeMessage(c.realms...))
	challenge = appendKV(challenge, "qop", mbytes.MakeMessage(c.qop...))
	challenge = appendKV(challenge, "stale", c.stale)
	challenge = appendKV(challenge, "charset", c.charset)

	return mbytes.MakeMessage(challenge...)
}

func (c *challenge) ParseChallenge(challenge []byte) error {
	fmap := newFieldMapper()
	fmap.Add("algorithm", &(c.algo))
	fmap.Add("charset", &(c.charset))
	fmap.Add("nonce", &(c.nonce))
	fmap.Add("stale", &(c.stale))

	return mbytes.EachField(challenge, func(field []byte) error {
		key, val := mbytes.ExtractKeyValue(field, '=')

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
