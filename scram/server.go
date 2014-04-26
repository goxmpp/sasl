package scram

import (
	"bytes"

	"github.com/azhavnerchik/sasl"
)

type Server struct {
	*scram
}

func NewServer(h HashConstructor, gen sasl.SaltGenerator) *Server {
	return &Server{newScram(h, false, gen)}
}

// Returns AuthID for current authentication session.
// If Client First message didn't provide AuthID - UserName will be used
func (s *Server) AuthID() string {
	if len(s.auth_id) != 0 {
		return string(s.auth_id)
	}
	return string(s.username)
}

// Returns UserName provided for Client First message
func (s *Server) UserName() string {
	return string(s.username)
}

// Generates Server First message. SaltPassword should be called before this method usage
func (s *Server) First() []byte {
	return s.serverFirst()
}

// Generates Server Final Message
func (s *Server) Final() []byte {
	return makeKeyValue('v', sasl.Base64ToBytes(s.verification()))
}

// Parses Client First message and populates Scram's internal fields
// related to binding, auth_id, username, cnonce
func (s *Server) ParseClientFirst(client_first []byte) error {
	auth_pref := []byte{'a', '='}

	if err := validateMessage(client_first); err != nil {
		return err
	}

	return sasl.EachToken(client_first, ',', func(token []byte) error {
		switch {
		case len(token) == 1 && (token[0] == 'n' || token[0] == 'y'):
			s.binding = token[0]
		case len(token) == 0 || bytes.HasPrefix(token, auth_pref):
			if bytes.HasPrefix(token, auth_pref) {
				_, v := sasl.ExtractKeyValue(token, '=')
				s.auth_id = deprepare(v)
			}
		case bytes.HasPrefix(token, []byte{'n', '='}):
			_, v := sasl.ExtractKeyValue(token, '=')
			s.username = deprepare(v)
		case bytes.HasPrefix(token, []byte{'r', '='}):
			_, v := sasl.ExtractKeyValue(token, '=')
			s.client_nonce = v
		default:
			return WrongClientMessage("Unknown field")
		}
		return nil
	})
}

// Checks Client Final message checking binding and proof values
func (s *Server) CheckClientFinal(client_final []byte) error {
	if err := s.checkBinding(client_final); err != nil {
		return err
	}

	proof, err := extractProof(client_final)
	if err != nil {
		return err
	}

	if !s.checkProof(proof) {
		return WrongClientMessage("Wrong proof provided")
	}

	return nil
}
