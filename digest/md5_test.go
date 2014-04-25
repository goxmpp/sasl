package digest_test

import (
	"testing"

	"github.com/azhavnerchik/sasl/digest"
)

const (
	std_challenge_realm   = "elwood.innosoft.com"
	std_challenge_qop     = "auth"
	std_challenge_nonce   = "OA6MG9tEQGm2hh"
	std_challenge_algo    = "md5-sess"
	std_challenge_charset = "utf-8"

	std_reply_realm     = "elwood.innosoft.com"
	std_reply_nonce     = "OA6MG9tEQGm2hh"
	std_reply_digesturi = "imap/elwood.innosoft.com"
	std_reply_qop       = "auth"
	std_reply_nc        = "00000001"
	std_reply_cnonce    = "OA6MHXh6VqTrRk"
	std_reply_response  = "d388dad90d4bbd760a152321f2143af7"
	std_reply_username  = "chris"
	std_reply_charset   = "utf-8"

	std_password = "secret"

	std_challenge = `realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",algorithm=md5-sess,charset=utf-8`
	//nonce="4f41364d4858683656715472526b",algorithm="md5-sess",realm="elwood.innosoft.com",qop="auth",charset="utf-8"
	std_respnse = `charset=utf-8,username="chris",realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",nc=00000001,cnonce="OA6MHXh6VqTrRk",digest-uri="imap/elwood.innosoft.com",response=d388dad90d4bbd760a152321f2143af7,qop=auth`
)

type StdGenerator struct{}

func (g StdGenerator) GetNonce(ln int) []byte {
	if ln == 16 {
		return []byte(std_challenge_nonce) // Client's nonce
	}

	return []byte(std_reply_cnonce) // Server's nonce
}

func TestStdExample(t *testing.T) {
	m := digest.NewMD5(&StdGenerator{})

	m.SetChallengeRealms(std_challenge_realm)
	if err := m.SetAlgorithm("md5-sess"); err != nil {
		t.Fatal("Could not get algorithm:", err)
	}
	t.Logf("Challenge %s", m.Challenge())
	m.SetQOP("auth")
	m.SetRealm(std_challenge_realm)
	t.Logf("Response  %s", m.Response(std_reply_username, std_password))
}
