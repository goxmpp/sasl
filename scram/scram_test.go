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

type StdGenerator struct{}

func (g *StdGenerator) GetNonce(ln int) []byte {
	if ln == 21 {
		return []byte("fyko+d2lbbFgONRv9qkxdawL") // Client's nonce
	}

	return []byte("3rfcNHYJY1ZVvWVs7j") // Server's nonce
}

func (g StdGenerator) GetSalt(ln int) []byte {
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
	mocgen := &StdGenerator{}
	c := NewClient(sha1.New, mocgen)

	if string(c.First(username)) != std_expect_client_first {
		t.Log("Expected", std_expect_client_first, "Got", string(c.First(username)))
		t.Fatal("Client First doesn't match expected Client First")
	}

	s := NewServer(sha1.New, mocgen)
	if string(s.First()) != std_expect_server_first {
		t.Log("Expected", std_expect_server_first, "Got", string(s.First()))
		t.Fatal("Server First doesn't match expected Server First")
	}

	c.SaltPassword([]byte(password))
	s.SaltPassword([]byte(password))
	if string(c.Final()) != std_expect_client_final {
		t.Log("\nExpected", std_expect_client_final, "\nGot     ", string(c.Final()))
		t.Fatal("Client Final doesn't match expected Client Final")
	}

	if base64.StdEncoding.EncodeToString(c.proof()) != std_base64_proof {
		t.Log("Epected", std_base64_proof, "Got", base64.StdEncoding.EncodeToString(c.proof()))
		t.Fatal("Wrong proof value generated")
	}

	eproof, err := extractProof([]byte(std_expect_client_final))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(c.proof(), eproof) {
		t.Log(c.proof())
		t.Log(eproof)
		t.Logf("\nExpected %x\nGot      %x", eproof, c.proof())
		t.Fatal("Wrong proof value generated")
	}

	s.ParseClientFirst(c.First(username))
	if !bytes.Equal(c.proof(), s.proof()) {
		t.Fatal("Client and Server should generate same proof")
	}

	if err := s.CheckClientFinal([]byte(std_expect_client_final)); err != nil {
		t.Fatal("Proof should be valid", err)
	}

	if string(s.Final()) != std_expect_server_final {
		t.Log("Expected", std_expect_server_final, "Got", s.Final())
		t.Fatal("Server Final doesn't match expected Server Final")
	}

	if err := c.CheckServerFinal([]byte(std_expect_server_final)); err != nil {
		t.Fatal("Verification check failed", err)
	}

	if std_base64_verification != base64.StdEncoding.EncodeToString(s.verification()) {
		t.Log("Epected", std_base64_verification, "Got", base64.StdEncoding.EncodeToString(s.verification()))
		t.Fatal("Wrong verification value generated")
	}
}

func TestClientParsing(t *testing.T) {
	mocgen := &StdGenerator{}
	s := NewServer(sha1.New, mocgen)

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
	mocgen := &StdGenerator{}
	s := NewClient(sha1.New, mocgen)

	s.First(username) // Just to ganerate nonces and other stuff

	if err := s.ParseServerFirst([]byte(std_expect_server_first)); err != nil {
		t.Fatal("Error parsing Server First:", err)
	}

	if string(s.nonce()) != std_nonce {
		t.Fatal("Nonce doesn't match")
	}

}
