package md5

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/azhavnerchik/sasl/util"
)

const A2_AUTH_SUFFIX = "00000000000000000000000000000000"

type response struct {
	realm       []byte
	username    []byte
	nonce       []byte
	cnonce      []byte
	nc          []byte
	server_type []byte
	host        []byte
	digest_uri  []byte
	charset     []byte
	auth_id     []byte
	response    []byte
	qop         []byte
	ok          bool
}

func newResponse() *response {
	return &response{}
}

func (r *response) ParseResponse(data []byte, c *challenge) error {
	return util.EachToken(data, ',', func(token []byte) error {
		key, val := util.ExtractKeyValue(token, '=')

		val = bytes.Trim(val, "\"")
		switch string(key) {
		case "username":
			r.username = val
		case "realm":
			r.realm = val
		case "nonce":
			r.nonce = val
		case "cnonce":
			r.cnonce = val
		case "nc":
			r.nc = val
		case "serv-type":
			r.server_type = val
		case "host":
			r.host = val
		case "digest-uri":
			r.digest_uri = val
		case "response":
			r.response = val
		case "charset":
			r.charset = val
		case "authzid":
			r.auth_id = val
		case "qop":
			r.qop = val
		default:
			return fmt.Errorf("Unknown parameter '%s' provided", key)
		}
		return nil
	})
}

func (r *response) Validate(password []byte, c *challenge) error {
	if !bytes.Equal(r.nonce, c.nonce) {
		return errors.New("Wrong nonce replied")
	}

	//if r.host != state.Host {
	//	return errors.New("Wrong host replied")
	//}

	if len(c.realms) > 0 {
		rvalid := false
		for _, realm := range c.realms {
			if bytes.Equal(r.realm, realm) {
				rvalid = true
				break
			}
		}

		if !rvalid {
			return errors.New("Wrong realm received from client")
		}
	}

	if !bytes.Equal(r.generateHash(c, password), r.response) {
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

func (r *response) generateHash(c *challenge, password []byte) []byte {
	x := md5.Sum(makeMessage(r.username, r.realm, password))

	start_str := makeMessage(x[:], c.nonce, r.cnonce)
	if len(r.auth_id) > 0 {
		start_str = makeMessage(start_str, r.auth_id)
	}
	bstart := md5.Sum(start_str)
	start := bytesToHex(bstart[:])

	end_str := makeMessage([]byte("AUTHENTICATE"), r.digest_uri)
	if bytes.Equal(c.qop, []byte("auth-int")) || bytes.Equal(c.qop, []byte("auth-conf")) {
		end_str = makeMessage(end_str, []byte(A2_AUTH_SUFFIX))
	}
	bend := md5.Sum(end_str)
	end := bytesToHex(bend[:])

	hash := md5.Sum(makeMessage(start, c.nonce, r.nc, r.cnonce, c.qop, end))
	return bytesToHex(hash[:])
}
