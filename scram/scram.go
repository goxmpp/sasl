package scram

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
)

type Options struct {
	UserName          string
	GetPassword       func(username string) string
	GetSaltedPassword func(username string) (salted_passwd []byte, salt []byte, iterations int)
}

type scram struct {
	cons func() hash.Hash

	password        string
	salted_password []byte
	salt            []byte
	iterations      int
	cnonce          string
	nonce           string
	proof           []byte
	username        string
	auth_id         string
	binding         byte
}

func New(cons func() hash.Hash, opts Options) *scram {
	return &scram{}
}

func (s *scram) ClientFirst() string {
	return fmt.Sprintf("%s,%s", s.bindString(), s.bareClientFirst())
}

func (s *scram) ServerFirst() string {
	return fmt.Sprintf("r=%s,s=%s,i=%d", s.nonce, base64.StdEncoding.EncodeToString(s.salt), s.iterations)
}

func (s *scram) ClientReply() string {
	if len(s.proof) == 0 {
		s.genProof()
	}

	return fmt.Sprintf("%s,p=%s", s.clientReplyNotProof(), base64.StdEncoding.EncodeToString(s.proof))
}

func (s *scram) ServerReply() string {
	ss := base64.StdEncoding.EncodeToString(s.getServerSignature(s.authMessage(), s.getServerKey()))
	return fmt.Sprintf("v=%s", ss)
}

func (s *scram) ParseClientFirst(client_first string) {

}

func (s *scram) ParseServerFirst(server_first string) {

}

func (s *scram) CheckProof() bool {
	if len(s.salted_password) == 0 {
		s.SaltPassword(s.password)
	}

	// Get Client and Server Keys
	clientk := s.getClientKey()

	// Get Stored Key
	storek := s.getHash(clientk)

	// Build Auth Message
	auth := s.authMessage()

	client_sig := s.getClientSignature(auth, storek)

	rck := byteXOR(client_sig, s.proof)

	return fmt.Sprintf("%x", s.getHash(rck)) == fmt.Sprintf("%x", storek)
}

func (s *scram) getHash(client_key []byte) []byte {
	h := s.cons()
	h.Write(client_key)
	return h.Sum(nil)
}

func (s *scram) genProof() {
	if len(s.salted_password) == 0 {
		s.SaltPassword(s.password)
	}

	// Get Client and Server Keys
	clientk := s.getClientKey()

	// Get Stored Key
	storek := s.getHash(clientk)

	// Build Auth Message
	auth := s.authMessage()

	client_sig := s.getClientSignature(auth, storek)

	// Generate Proof
	s.proof = byteXOR(client_sig, clientk)
}

func (s *scram) SaltPassword(password string) ([]byte, []byte, int) {
	mac := hmac.New(s.cons, []byte(password))

	salt := make([]byte, 0, len(s.salt))
	copy(salt, s.salt)
	salt = append(salt, 0x00, 0x00, 0x00, 0x01)

	mac.Write(salt)
	result := mac.Sum(nil)

	prev := make([]byte, 0, len(result))
	prev = append(prev, result...)

	for i := 1; i < s.iterations; i++ {
		mac.Reset()
		mac.Write(prev)
		tmp := mac.Sum(nil)

		result = byteXOR(result, tmp)

		prev = tmp
	}

	s.salted_password = result

	return s.salted_password, s.salt, s.iterations
}

func (s *scram) bareClientFirst() string {
	return fmt.Sprintf("n=%s,r=%s", s.username, s.cnonce)
}

func (s *scram) bindString() string {
	authid := ""
	if len(s.auth_id) > 0 {
		authid = fmt.Sprintf("a=%s", s.auth_id)
	}
	return fmt.Sprintf("%c,%s", s.binding, authid)
}

func (s *scram) clientReplyNotProof() string {
	return fmt.Sprintf("c=%s,r=%s", base64.StdEncoding.EncodeToString([]byte(s.bindString())), s.nonce)
}

func (s *scram) authMessage() string {
	return strings.Join([]string{s.bareClientFirst(), s.ServerFirst(), s.clientReplyNotProof()}, ",")
}

func byteXOR(left, right []byte) []byte {
	res := make([]byte, len(left))
	for i := range left {
		res[i] = left[i] ^ right[i]
	}
	return res
}

func (s *scram) getClientKey() []byte {
	mac := hmac.New(s.cons, s.salted_password)
	mac.Write([]byte("Client Key"))
	return mac.Sum(nil)
}

func (s *scram) getServerKey() []byte {
	mac := hmac.New(s.cons, s.salted_password)
	mac.Write([]byte("Server Key"))
	return mac.Sum(nil)
}
func (s *scram) getServerSignature(auth string, serverk []byte) []byte {
	ssmac := hmac.New(s.cons, serverk)
	ssmac.Write([]byte(auth))
	return ssmac.Sum(nil)
}

func (s *scram) getClientSignature(auth string, storek []byte) []byte {
	skmac := hmac.New(s.cons, storek)
	skmac.Write([]byte(auth))
	return skmac.Sum(nil)
}
