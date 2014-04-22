package scram

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"testing"
)

const (
	username                = "user"
	password                = "pencil"
	std_base64_proof        = "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
	std_base64_verification = "rmF9pqV8S7suAoZWja4dJRkFsKQ="

	std_cnonce = "fyko+d2lbbFgONRv9qkxdawL"
	std_nonce  = "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"

	std_expect_client_first = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"
	std_expect_server_first = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
	std_expect_client_final = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
	std_expect_server_final = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ="
)

type StdGenerator struct {
	counter int
}

func (g *StdGenerator) GetNonce() string {
	if g.counter == 0 {
		g.counter = 1
		return "fyko+d2lbbFgONRv9qkxdawL" // Client's nonce
	}

	g.counter = 0
	return "3rfcNHYJY1ZVvWVs7j" // Server's nonce
}

func (g StdGenerator) GetSalt() []byte {
	b, err := base64.StdEncoding.DecodeString("QSXCR+Q6sek8bf92")
	if err != nil {
		panic(err)
	}
	return b
}

func (g StdGenerator) GetIterations() int {
	return 4096
}

func TestStandardExample(t *testing.T) {
	mocgen := &StdGenerator{counter: 0}
	s := New(sha1.New, false, mocgen)

	if s.ClientFirst(username) != std_expect_client_first {
		t.Log("Expected", std_expect_client_first, "Got", s.ClientFirst(username))
		t.Fatal("Client First doesn't match expected Client First")
	}

	if s.ServerFirst() != std_expect_server_first {
		t.Log("Expected", std_expect_server_first, "Got", s.ServerFirst())
		t.Fatal("Server First doesn't match expected Server First")
	}

	s.SaltPassword([]byte(password))
	if s.ClientFinal() != std_expect_client_final {
		t.Log("Expected", std_expect_client_final, "Got", s.ClientFinal())
		t.Fatal("Client Final doesn't match expected Client Final")
	}

	if base64.StdEncoding.EncodeToString(s.proof()) != std_base64_proof {
		t.Log("Epected", std_base64_proof, "Got", base64.StdEncoding.EncodeToString(s.proof()))
		t.Fatal("Wrong proof value generated")
	}

	eproof, err := ExtractProof([]byte(std_expect_client_final))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(s.proof(), eproof) {
		t.Logf("Expected %x\nGot      %x", eproof, s.proof())
		t.Fatal("Wrong proof value generated")
	}

	if !s.CheckProof(eproof) {
		t.Fatal("Proof should be valid")
	}

	if s.ServerFinal() != std_expect_server_final {
		t.Log("Expected", std_expect_server_final, "Got", s.ServerFinal())
		t.Fatal("Server Final doesn't match expected Server Final")
	}

	if std_base64_verification != base64.StdEncoding.EncodeToString(s.verification()) {
		t.Log("Epected", std_base64_verification, "Got", base64.StdEncoding.EncodeToString(s.verification()))
		t.Fatal("Wrong verification value generated")
	}
}

func TestClientParsing(t *testing.T) {
	mocgen := &StdGenerator{counter: 0}
	s := New(sha1.New, false, mocgen)

	if err := s.ParseClientFirst([]byte(std_expect_client_first)); err != nil {
		t.Fatal("Error parsing Client First:", err)
	}

	if s.cnonce() != std_cnonce {
		t.Fatal("CNonce doesn't match")
	}

	if s.AuthID() != username {
		t.Fatal("AuthID was parsed incorrectly")
	}

	if s.UserName() != username {
		t.Fatal("Username doesn't match")
	}

	if s.BindingSupported() {
		t.Fatal("Binding doens't match")
	}

	if err := s.ParseClientFirst([]byte("w=rong")); err == nil {
		t.Fatal("Should fail on wrong Client First message")
	} else {
		t.Log("Wrong message parsing returned:", err)
	}
}

func TestServerParsing(t *testing.T) {
	mocgen := &StdGenerator{counter: 0}
	s := New(sha1.New, false, mocgen)

	s.ClientFirst(username) // Just to ganerate nonces and other stuff

	if err := s.ParseServerFirst([]byte(std_expect_server_first)); err != nil {
		t.Fatal("Error parsing Server First:", err)
	}

	if s.nonce() != std_nonce {
		t.Fatal("Nonce doesn't match")
	}

}
