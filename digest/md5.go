package digest

import (
	"errors"

	"github.com/azhavnerchik/sasl"
)

const (
	nonce_size  = 16
	cnonce_size = 10
)

type MD5 struct {
	*challenge
	*response
}

var DefaultGenerator sasl.Generator

func NewMD5(gen sasl.NonceGenerator) *MD5 {
	if gen == nil {
		gen = DefaultGenerator
	}

	return &MD5{challenge: newChallenge(gen), response: newResponse(gen)}
}

func (m *MD5) AuthID() string {
	if len(m.response.auth_id) > 0 {
		return string(m.response.auth_id)
	}
	return string(m.response.username)
}

func (m *MD5) UserName() string {
	return string(m.response.username)
}

func (m *MD5) Response(username, password string) []byte {
	m.response.HashPassword([]byte(password))
	return m.response.Response([]byte(username), m.challenge)
}

func (m *MD5) ResponseHashed(username string, password []byte) []byte {
	m.response.SetPasswordHash(password)
	return m.response.Response([]byte(username), m.challenge)
}

func (m *MD5) Final() []byte {
	if m.response.ok {
		return []byte("rspauth") // TODO reply something else on failed authentication
	}
	return []byte{}
}

func (m *MD5) Validate(password string) error {
	m.response.HashPassword([]byte(password))
	return m.response.Validate(m.challenge)
}

func (m *MD5) ValidateHashed(password []byte) error {
	m.response.SetPasswordHash(password)
	return m.response.Validate(m.challenge)
}

func (m *MD5) ParseResponse(response []byte) error {
	return m.response.ParseResponse(response, m.challenge)
}

func (m *MD5) SetAlgorithm(algo string) error {
	if algo != "md5" && algo != "md5-sess" {
		return errors.New("Wrong algorithm specified")
	}

	m.challenge.algo = []byte(algo)
	m.response.algo = []byte(algo)
	return nil
}
