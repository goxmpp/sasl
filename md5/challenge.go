package md5

import (
	"crypto/rand"

	"github.com/azhavnerchik/sasl/util"
)

type challenge struct {
	realms  [][]byte
	nonce   []byte
	qop     []byte
	charset []byte
	algo    []byte
}

func newChallenge(srealms []string, alg []byte) *challenge {
	nonce := make([]byte, 14)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	realms := make([][]byte, len(srealms))
	for i, realm := range srealms {
		realms[i] = []byte(realm)
	}
	return &challenge{
		realms: realms,
		nonce:  bytesToHex(nonce),
		qop:    []byte("auth"),
		algo:   alg,
	}
}

func makeKV(key string, val []byte) []byte {
	return util.MakeKeyValue([]byte(key), append(append([]byte{'"'}, val...), '"'))
}

func (c *challenge) Challenge() []byte {
	str := [][]byte{makeKV("nonce", c.nonce), makeKV("algorithm", c.algo)}
	for _, realm := range c.realms {
		str = append(str, makeKV("realm", realm))
	}
	if len(c.qop) > 0 {
		str = append(str, makeKV("qop", c.qop))
	}
	if len(c.charset) > 0 {
		str = append(str, makeKV("charset", c.charset))
	}

	return util.MakeMessage(str...)
}

func (m *challenge) ParseChallenge(challenge []byte) error {
	return nil
}
