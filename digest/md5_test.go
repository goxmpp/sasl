package digest_test

import (
	"testing"

	"github.com/azhavnerchik/sasl/digest"
)

const (
	std_challenge_realm  = "testrealm@host.com"
	std_challenge_qop    = "auth,auth-int"
	std_challenge_nonce  = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	std_challenge_opaque = "5ccc069c403ebaf9f0171e9517f40e41"

	std_reply_realm    = "testrealm@host.com"
	std_reply_nonce    = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	std_reply_uri      = "/dir/index.html"
	std_reply_qop      = "auth"
	std_reply_nc       = 00000001
	std_reply_cnonce   = "0a4f113b"
	std_reply_response = "6629fae49393a05397450978507c4ef1"
	std_reply_opaque   = "5ccc069c403ebaf9f0171e9517f40e41"
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
	_ = m
}
