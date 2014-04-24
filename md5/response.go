package md5

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"

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

func newResponse() *response {
	return &response{}
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

func (r *response) Response() []byte {
	return []byte{}
}

func contains(find []byte, arr [][]byte) bool {
	for _, item := range arr {
		if bytes.Equal(find, item) {
			return true
		}
	}
	return false
}

func (r *response) Validate(password []byte, c *challenge) error {
	if !bytes.Equal(r.nonce, c.nonce) {
		return errors.New("Wrong nonce replied")
	}

	if len(c.realms) > 0 && !contains(r.realm, c.realms) {
		return errors.New("Wrong realm received from client")
	}

	if len(c.qop) > 0 && !contains(r.qop, c.qop) {
		return errors.New("Wrong QOP received from client")
	}

	if !bytes.Equal(r.generateHash(password), r.response) {
		return errors.New("Wrong response hash received")
	}
	r.ok = true

	return nil
}

func makeMessage(tokens ...[]byte) []byte {
	return bytes.Join(tokens, []byte{':'})
}

func bytesToHex(src []byte) []byte {
	res := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(res, src)
	return res
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

func (r *response) generateHash(password []byte) []byte {
	r.HashPassword(password)

	bstart := makeMessage(r.hpassword, r.nonce, r.cnonce)
	if len(r.auth_id) > 0 {
		bstart = makeMessage(bstart, r.auth_id)
	}
	start := md5.Sum(bstart)
	hstart := bytesToHex(start[:])

	bend := makeMessage([]byte("AUTHENTICATE"), r.digest_uri)
	if bytes.Equal(r.qop, []byte("auth-int")) || bytes.Equal(r.qop, []byte("auth-conf")) {
		bend = makeMessage(bend, []byte(A2_AUTH_SUFFIX))
	}
	end := md5.Sum(bend)
	hend := bytesToHex(end[:])

	bhash := makeMessage(hstart, r.nonce)
	if len(r.qop) > 0 {
		bhash = makeMessage(bhash, r.nc, r.cnonce, r.qop)
	}
	hash := md5.Sum(makeMessage(bhash, hend))
	return bytesToHex(hash[:])
}
