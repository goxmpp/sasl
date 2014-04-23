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

func (g *StdGenerator) GetNonce() []byte {
	if g.counter == 0 {
		g.counter = 1
		return []byte("fyko+d2lbbFgONRv9qkxdawL") // Client's nonce
	}

	g.counter = 0
	return []byte("3rfcNHYJY1ZVvWVs7j") // Server's nonce
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

	if string(s.ClientFirst(username)) != std_expect_client_first {
		t.Log("Expected", std_expect_client_first, "Got", s.ClientFirst(username))
		t.Fatal("Client First doesn't match expected Client First")
	}

	if string(s.ServerFirst()) != std_expect_server_first {
		t.Log("Expected", std_expect_server_first, "Got", string(s.ServerFirst()))
		t.Fatal("Server First doesn't match expected Server First")
	}

	s.SaltPassword([]byte(password))
	if string(s.ClientFinal()) != std_expect_client_final {
		t.Log("\nExpected", std_expect_client_final, "\nGot     ", string(s.ClientFinal()))
		t.Fatal("Client Final doesn't match expected Client Final")
	}

	if base64.StdEncoding.EncodeToString(s.proof()) != std_base64_proof {
		t.Log("Epected", std_base64_proof, "Got", base64.StdEncoding.EncodeToString(s.proof()))
		t.Fatal("Wrong proof value generated")
	}

	eproof, err := extractProof([]byte(std_expect_client_final))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s.proof(), eproof) {
		t.Log(s.proof())
		t.Log(eproof)
		t.Logf("\nExpected %x\nGot      %x", eproof, s.proof())
		t.Fatal("Wrong proof value generated")
	}

	if err := s.CheckClientFinal([]byte(std_expect_client_final)); err != nil {
		t.Fatal("Proof should be valid", err)
	}

	if string(s.ServerFinal()) != std_expect_server_final {
		t.Log("Expected", std_expect_server_final, "Got", s.ServerFinal())
		t.Fatal("Server Final doesn't match expected Server Final")
	}

	if err := s.CheckServerFinal([]byte(std_expect_server_final)); err != nil {
		t.Fatal("Verification check failed", err)
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

	if string(s.cnonce()) != std_cnonce {
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

	if string(s.nonce()) != std_nonce {
		t.Fatal("Nonce doesn't match")
	}

}
