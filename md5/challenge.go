package md5

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/azhavnerchik/sasl/util"
)

type challenge struct {
	realms  [][]byte
	nonce   []byte
	qop     [][]byte // auth or auth-int
	charset []byte
	algo    []byte // MD5 or MD5-sess, Default MD5
	opaque  []byte
	stale   []byte // 'TRUE' or 'FALSE'
	domain  []byte
}

func newChallenge() *challenge {
	nonce := make([]byte, 14)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return &challenge{
		nonce: bytesToHex(nonce),
		algo:  []byte("MD5"),
	}
}

func (c *challenge) SetDomain(domain string) {
	c.domain = []byte(domain)
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

func (c *challenge) SetRealm(srealms ...string) {
	realms := make([][]byte, len(srealms))
	for i, realm := range srealms {
		realms[i] = []byte(realm)
	}
	c.realms = realms
}

func makeKV(key string, val []byte) []byte {
	return util.MakeKeyValue([]byte(key), append(append([]byte{'"'}, val...), '"'))
}

func appendKV(kvs [][]byte, key string, val []byte) [][]byte {
	if len(val) > 0 {
		return append(kvs, makeKV(key, val))
	}
	return kvs
}

func (c *challenge) Challenge() []byte {
	challenge := [][]byte{makeKV("nonce", c.nonce), makeKV("algorithm", c.algo)}
	challenge = appendKV(challenge, "realm", util.MakeMessage(c.realms...))
	challenge = appendKV(challenge, "qop", util.MakeMessage(c.qop...))
	challenge = appendKV(challenge, "domain", c.domain)
	challenge = appendKV(challenge, "opaque", c.opaque)
	challenge = appendKV(challenge, "stale", c.stale)
	challenge = appendKV(challenge, "charset", c.charset)

	return util.MakeMessage(challenge...)
}

func (c *challenge) ParseChallenge(challenge []byte) error {
	fmap := newFieldMapper()
	fmap.Add("algorithm", &(c.algo))
	fmap.Add("domain", &(c.domain))
	fmap.Add("charset", &(c.charset))
	fmap.Add("nonce", &(c.nonce))
	fmap.Add("opaque", &(c.opaque))
	fmap.Add("stale", &(c.stale))

	return util.EachField(challenge, func(field []byte) error {
		key, val := util.ExtractKeyValue(field, '=')

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
