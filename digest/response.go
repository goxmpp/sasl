package digest

import (
	"bytes"
	"crypto/md5"
	"errors"

	"github.com/azhavnerchik/sasl/generator"
	"github.com/azhavnerchik/sasl/util"
)

const A2_AUTH_SUFFIX = "00000000000000000000000000000000"

type response struct {
	realm, username, nonce, cnonce, nc     []byte
	server_type, host, digest_uri, charset []byte
	auth_id, response, qop                 []byte
	ok                                     bool
	hpassword                              []byte
}

func newResponse(gen generator.NonceGenerator) *response {
	return &response{
		cnonce: util.BytesToHex(gen.GetNonce(cnonce_size)),
		nc:     []byte{0x01}, // Need to generate this somehow
	}
}

// Parses client's response received by server and initialize internal state from it
func (r *response) ParseResponse(data []byte, c *challenge) error {
	fmap := newFieldMapper()
	fmap.Add("username", &(r.username))
	fmap.Add("realm", &(r.realm))
	fmap.Add("nonce", &(r.nonce))
	fmap.Add("cnonce", &(r.cnonce))
	fmap.Add("nc", &(r.nc))
	fmap.Add("host", &(r.host))
	fmap.Add("digest-uri", &(r.digest_uri))
	fmap.Add("response", &(r.response))
	fmap.Add("charset", &(r.charset))
	fmap.Add("authzid", &(r.auth_id))
	fmap.Add("qop", &(r.qop))

	return util.EachToken(data, ',', func(token []byte) error {
		key, val := util.ExtractKeyValue(token, '=')

		if err := fmap.Set(string(key), bytes.Trim(val, "\"")); err != nil {
			return err
		}
		return nil
	})
}

func (r *response) SetRealm(realm string) {
	r.realm = []byte(realm)
}

func (r *response) SetSetverType(stype string) {
	r.server_type = []byte(stype)
}

func (r *response) SetAuthID(auth_id string) {
	r.auth_id = []byte(auth_id)
}

func (r *response) Response(username []byte, c *challenge) []byte {
	repl := [][]byte{
		makeKV("nonce", r.nonce), makeKV("cnonce", r.cnonce),
		makeKV("response", r.generateHash()), makeKV("nc", r.nc),
		makeKV("username", r.username),
	}
	repl = appendKV(repl, "realm", r.realm)
	repl = appendKV(repl, "qop", r.qop)
	repl = appendKV(repl, "authzid", r.auth_id)
	repl = appendKV(repl, "digest-uri", r.digest_uri)
	repl = appendKV(repl, "charset", r.charset)
	repl = appendKV(repl, "host", r.host)
	repl = appendKV(repl, "serv-type", r.server_type)

	return util.MakeMessage(repl...)
}

func contains(find []byte, arr [][]byte) bool {
	for _, item := range arr {
		if bytes.Equal(find, item) {
			return true
		}
	}
	return false
}

func (r *response) Validate(c *challenge) error {
	if !bytes.Equal(r.nonce, c.nonce) {
		return errors.New("Wrong nonce replied")
	}

	if len(c.realms) > 0 && !contains(r.realm, c.realms) {
		return errors.New("Wrong realm received from client")
	}

	if len(c.qop) > 0 && !contains(r.qop, c.qop) {
		return errors.New("Wrong QOP received from client")
	}

	if !bytes.Equal(r.generateHash(), r.response) {
		return errors.New("Wrong response hash received")
	}
	r.ok = true

	return nil
}

func makeMessage(tokens ...[]byte) []byte {
	return bytes.Join(tokens, []byte{':'})
}

// Sets internal hashed password. Enables users to store passwords hashed
func (r *response) SetPasswordHash(hpassword []byte) {
	r.hpassword = hpassword
}

// Hashes password and initializes internal hashed password field which
// then will be used for further authentication processing
func (r *response) HashPassword(password []byte) []byte {
	x := md5.Sum(makeMessage(r.username, r.realm, password))
	if !bytes.Equal(r.hpassword, x[:]) {
		r.hpassword = x[:]
	}
	return x[:]
}

func (r *response) generateHash() []byte {
	bstart := makeMessage(r.hpassword, r.nonce, r.cnonce)
	if len(r.auth_id) > 0 {
		bstart = makeMessage(bstart, r.auth_id)
	}
	start := md5.Sum(bstart)
	hstart := util.BytesToHex(start[:])

	bend := makeMessage([]byte("AUTHENTICATE"), r.digest_uri)
	if contains(r.qop, [][]byte{[]byte("auth-int"), []byte("auth-conf")}) {
		bend = makeMessage(bend, []byte(A2_AUTH_SUFFIX))
	}
	end := md5.Sum(bend)
	hend := util.BytesToHex(end[:])

	bhash := makeMessage(hstart, r.nonce)
	if len(r.qop) > 0 {
		bhash = makeMessage(bhash, r.nc, r.cnonce, r.qop)
	}
	hash := md5.Sum(makeMessage(bhash, hend))
	return util.BytesToHex(hash[:])
}
