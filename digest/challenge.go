package digest

import (
	"bytes"

	"github.com/goxmpp/sasl"
)

type challenge struct {
	realms  [][]byte
	nonce   []byte
	qop     [][]byte // auth or auth-int
	charset []byte
	algo    []byte // md5 or md5-sess, Default md5
	stale   []byte // 'TRUE' or 'FALSE'
}

func newChallenge(opts *Options) *challenge {
	algo, charset, realms, qops := "md5", "utf-8", [][]byte{}, [][]byte{[]byte("auth")}
	if opts.Algorithm != "" {
		algo = opts.Algorithm
	}
	if opts.Charset != "" {
		algo = opts.Charset
	}

	if len(opts.QOPs) > 0 {
		qops = make([][]byte, 0)
		for _, qop := range opts.QOPs {
			qops = append(qops, []byte(qop))
		}
	}

	for _, realm := range opts.Realms {
		realms = append(realms, []byte(realm))
	}

	return &challenge{
		nonce:   opts.Generator.GetNonce(nonce_size),
		algo:    []byte(algo),
		qop:     qops,
		charset: []byte(charset),
		realms:  realms,
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

func (c *challenge) challenge() []byte {
	challenge := [][]byte{makeKV("nonce", c.nonce), sasl.MakeKeyValue([]byte("algorithm"), c.algo)}
	for _, realm := range c.realms {
		challenge = appendKVQuoted(challenge, "realm", realm)
	}
	challenge = appendKVQuoted(challenge, "qop", sasl.MakeMessage(c.qop...))
	challenge = appendKVQuoted(challenge, "stale", c.stale)
	challenge = appendKV(challenge, "charset", c.charset)

	return sasl.MakeMessage(challenge...)
}

func (c *challenge) parseChallenge(challenge []byte) error {
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
