package digest

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"strconv"

	"github.com/goxmpp/sasl"
)

const A2_AUTH_SUFFIX = "00000000000000000000000000000000"

type response struct {
	realm, username, nonce, cnonce         []byte
	server_type, host, digest_uri, charset []byte
	auth_id, resp, qop                     []byte
	ok                                     bool
	hpassword                              []byte
	nonce_count                            int
}

func newResponse(opts *Options) *response {
	return &response{
		cnonce:      opts.Generator.GetNonce(cnonce_size),
		nonce_count: 1, // Need to generate this somehow
		charset:     []byte(opts.Charset),
		realm:       []byte(opts.Realm),
		qop:         []byte(opts.QOP),
		digest_uri:  []byte(opts.DigestURI),
		server_type: []byte(opts.ServerType),
		auth_id:     []byte(opts.AuthID),
	}
}

func (r *response) nc() []byte {
	return []byte(fmt.Sprintf("%08x", r.nonce_count))
}

// Parses client's response received by server and initialize internal state from it
func (r *response) parseResponse(data []byte, c *challenge) error {
	fmap := newFieldMapper()
	fmap.Add("username", &(r.username))
	fmap.Add("realm", &(r.realm))
	fmap.Add("nonce", &(r.nonce))
	fmap.Add("cnonce", &(r.cnonce))
	fmap.Add("host", &(r.host))
	fmap.Add("digest-uri", &(r.digest_uri))
	fmap.Add("response", &(r.resp))
	fmap.Add("charset", &(r.charset))
	fmap.Add("authzid", &(r.auth_id))
	fmap.Add("qop", &(r.qop))

	uniq := map[string]int{"username": 0, "realm": 0, "nonce": 0, "cnonce": 0, "nc": 0}

	return sasl.EachToken(data, ',', func(token []byte) error {
		if !bytes.Contains(token, []byte{'='}) {
			return fmt.Errorf("Token does not contain key value pair: %s", token)
		}

		key, val := sasl.ExtractKeyValue(token, '=')

		if _, ok := uniq[string(key)]; ok {
			uniq[string(key)] += 1
			if uniq[string(key)] > 1 {
				return fmt.Errorf("More than one occurance of %s found", key)
			}
		}

		switch string(key) {
		case "nc":
			v, err := strconv.Atoi(string(val))
			if err != nil {
				return fmt.Errorf("Wrong nc value: %s", err)
			}
			r.nonce_count = v
		default:
			if err := fmap.Set(string(key), bytes.Trim(val, "\"")); err != nil {
				return err
			}
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

func (r *response) SetQOP(qop string) {
	r.qop = []byte(qop) // TODO added checks
}

func (r *response) response(username []byte, c *challenge) []byte {
	r.username = username

	repl := [][]byte{
		makeKV("nonce", r.nonce), makeKV("cnonce", r.cnonce),
		sasl.MakeKeyValue([]byte("response"), r.generateHash()),
		sasl.MakeKeyValue([]byte("nc"), r.nc()), makeKV("username", r.username),
	}

	repl = appendKVQuoted(repl, "realm", r.realm)
	repl = appendKVQuoted(repl, "authzid", r.auth_id)
	repl = appendKVQuoted(repl, "digest-uri", r.digest_uri)
	repl = appendKVQuoted(repl, "host", r.host)
	repl = appendKVQuoted(repl, "serv-type", r.server_type)
	repl = appendKV(repl, "charset", r.charset)
	repl = appendKV(repl, "qop", r.qop)

	return sasl.MakeMessage(repl...)
}

func (r *response) validate(c *challenge) error {
	if !bytes.Equal(r.nonce, c.nonce) {
		return errors.New("Wrong nonce replied")
	}

	if len(c.realms) > 0 && !sasl.Contains(r.realm, c.realms) {
		return errors.New("Wrong realm received from client")
	}

	if len(c.qop) > 0 && !sasl.Contains(r.qop, c.qop) {
		return errors.New("Wrong QOP received from client")
	}

	if !bytes.Equal(r.generateHash(), r.resp) {
		return errors.New("Wrong response hash received")
	}
	r.ok = true

	return nil
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

func (r *response) genResponse(method []byte) []byte {
	bstart := makeMessage(r.hpassword, r.nonce, r.cnonce)
	if len(r.auth_id) > 0 {
		bstart = makeMessage(bstart, r.auth_id)
	}
	start := md5.Sum(bstart)
	hstart := sasl.BytesToHex(start[:])

	bend := makeMessage(method, r.digest_uri)
	if sasl.Contains(r.qop, [][]byte{[]byte("auth-int"), []byte("auth-conf")}) {
		bend = makeMessage(bend, []byte(A2_AUTH_SUFFIX))
	}
	end := md5.Sum(bend)
	hend := sasl.BytesToHex(end[:])

	hash := md5.Sum(makeMessage(hstart, r.nonce, r.nc(), r.cnonce, r.qop, hend))
	return sasl.BytesToHex(hash[:])
}

func (r *response) generateHash() []byte {
	return r.genResponse([]byte("AUTHENTICATE"))
}

func (r *response) responseAuth() []byte {
	return r.genResponse([]byte{})
}
