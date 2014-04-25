package digest

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"strconv"

	"github.com/azhavnerchik/sasl"
)

const A2_AUTH_SUFFIX = "00000000000000000000000000000000"

type response struct {
	realm, username, nonce, cnonce         []byte
	server_type, host, digest_uri, charset []byte
	auth_id, response, qop, algo           []byte
	ok                                     bool
	hpassword                              []byte
	nonce_count                            int
}

func newResponse(gen sasl.NonceGenerator) *response {
	return &response{
		cnonce:      sasl.BytesToHex(gen.GetNonce(nonce_size)),
		nonce_count: 1, // Need to generate this somehow
		charset:     []byte("utf-8"),
	}
}

func (r *response) nc() []byte {
	return []byte(fmt.Sprintf("%08x", r.nonce_count))
}

// Parses client's response received by server and initialize internal state from it
func (r *response) ParseResponse(data []byte, c *challenge) error {
	fmap := newFieldMapper()
	fmap.Add("username", &(r.username))
	fmap.Add("realm", &(r.realm))
	fmap.Add("nonce", &(r.nonce))
	fmap.Add("cnonce", &(r.cnonce))
	fmap.Add("host", &(r.host))
	fmap.Add("digest-uri", &(r.digest_uri))
	fmap.Add("response", &(r.response))
	fmap.Add("charset", &(r.charset))
	fmap.Add("authzid", &(r.auth_id))
	fmap.Add("qop", &(r.qop))
	fmap.Add("algorithm", &(r.algo))

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

func (r *response) Response(username []byte, c *challenge) []byte {
	r.username = username
	r.nonce = c.nonce
	r.algo = c.algo
	r.charset = c.charset

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
	repl = appendKV(repl, "algorithm", r.algo)
	repl = appendKV(repl, "charset", r.charset)
	repl = appendKV(repl, "qop", r.qop)

	return sasl.MakeMessage(repl...)
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

	if !bytes.Equal(r.algo, c.algo) {
		return errors.New("Wrong algorithm specified in client's reply")
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
	hstart := sasl.BytesToHex(start[:])

	bend := makeMessage([]byte("AUTHENTICATE"), r.digest_uri)
	if contains(r.qop, [][]byte{[]byte("auth-int"), []byte("auth-conf")}) {
		bend = makeMessage(bend, []byte(A2_AUTH_SUFFIX))
	}
	end := md5.Sum(bend)
	hend := sasl.BytesToHex(end[:])

	bhash := makeMessage(hstart, r.nonce)
	if len(r.qop) > 0 {
		bhash = makeMessage(bhash, r.nc(), r.cnonce, r.qop)
	}
	hash := md5.Sum(makeMessage(bhash, hend))
	return sasl.BytesToHex(hash[:])
}
