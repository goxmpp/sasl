package digest_test

import (
	"bytes"
	"sort"
	"strings"
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
	std_respnse   = `charset=utf-8,username="chris",realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",nc=00000001,cnonce="OA6MHXh6VqTrRk",digest-uri="imap/elwood.innosoft.com",response=3d249750661c0fd2296cdf4bb0ea7af1,qop=auth`
	std_respauth  = `rspauth=ea40f60335c427b5527b84dbabcdfffd`
	//std_respnse  = `charset=utf-8,username="chris",realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",nc=00000001,cnonce="OA6MHXh6VqTrRk",digest-uri="imap/elwood.innosoft.com",response=d388dad90d4bbd760a152321f2143af7,qop=auth`
)

type StdGenerator struct{}

func (g StdGenerator) GetNonce(ln int) []byte {
	if ln == 16 {
		return []byte(std_challenge_nonce) // Client's nonce
	}

	return []byte(std_reply_cnonce) // Server's nonce
}

func sortFields(str string) string {
	gs := strings.Split(str, ",")
	sort.Strings(gs)
	return strings.Join(gs, ",")
}

func TestStdExample(t *testing.T) {
	opts := &digest.Options{
		Generator: &StdGenerator{},
		Realms:    []string{std_challenge_realm},
		Algorithm: "md5-sess",
		QOPs:      []string{"auth"},
		DigestURI: std_reply_digesturi,
	}
	s := digest.NewServer(opts)

	got := sortFields(string(s.Challenge()))
	expect := sortFields(std_challenge)

	if got != expect {
		t.Logf("    Challenge %s", got)
		t.Logf("STD Challenge %s", expect)
		t.Fatal("Wrong challenge generated")
	}

	c := digest.NewClientFromChallenge([]byte(std_challenge), opts)
	rgot := sortFields(string(c.Response(std_reply_username, std_password)))
	rexpect := sortFields(std_respnse)
	if rgot != rexpect {
		t.Logf("    Response  %s", rgot)
		t.Logf("STD Response  %s", rexpect)
		t.Fatal("Wrong response")
	}

	s.ParseResponse(c.Response(std_reply_username, std_password))
	if err := s.Validate(std_password); err != nil {
		t.Fatal(err)
	}

	if err := s.Validate(std_password); err != nil {
		t.Fatal("Validation failed", err)
	}

	if !bytes.Equal(s.Final(), []byte(std_respauth)) {
		t.Log(string(s.Final()))
		t.Log(std_respauth)
		t.Fatal("Wrong Auth response")
	}
}
