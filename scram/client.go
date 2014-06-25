package scram

import (
	"bytes"
	"encoding/base64"
	"strconv"

	"github.com/goxmpp/sasl"
)

type Client struct {
	*scram
}

func NewClient(h HashConstructor, gen sasl.SaltGenerator) *Client {
	return &Client{newScram(h, false, gen)}
}

// Generates Client First message. Username whould be SASLprepared
func (s *Client) First(username string) []byte {
	s.username = prepare(username)
	return append(s.bindString(), s.bareClientFirst()...)
}

// Generated Client Final message. SaltPassword should be called before this method usage
func (s *Client) Final() []byte {
	return sasl.MakeMessage(s.clientReplyNotProof(), makeKeyValue('p', sasl.Base64ToBytes(s.proof())))
}

// Parses Server First message and populates Scram's internal fields
// like server nonce, salt, iterations count
func (s *Client) ParseServerFirst(server_first []byte) error {
	return sasl.EachToken(server_first, ',', func(token []byte) error {
		k, v := sasl.ExtractKeyValue(token, '=')
		if len(k) != 1 {
			return WrongServerMessage("Wrong key/value pair")
		}

		switch k[0] {
		case 'i':
			it, err := strconv.Atoi(string(v))
			if err != nil {
				return err
			}
			s.iterate = it
		case 'r':
			s.server_nonce = v
		case 's':
			salt := make([]byte, base64.StdEncoding.DecodedLen(len(v)))
			if _, err := base64.StdEncoding.Decode(salt, v); err != nil {
				return err
			}
			s.salt = salt
		default:
			return WrongServerMessage("Unknown value provided")
		}
		return nil
	})
}

// Checks Server Final message verifying server signature
func (s *Client) CheckServerFinal(sfinal []byte) error {
	b64ver, err := extractParameter(sfinal, 'v')
	if err != nil {
		return err
	}

	verification, err := base64.StdEncoding.DecodeString(string(b64ver))
	if err != nil {
		return err
	}

	if !bytes.Equal(s.verification(), verification) {
		return WrongServerMessage("Wrong verification provided")
	}
	return nil
}
