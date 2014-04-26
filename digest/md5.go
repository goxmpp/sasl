package digest

import "github.com/azhavnerchik/sasl"

const (
	nonce_size  = 16
	cnonce_size = 10
)

type digest struct {
	*challenge
	*response
}

type Server digest
type Client digest

type Options struct {
	Generator  sasl.NonceGenerator
	Realms     []string
	QOPs       []string
	QOP        string
	Realm      string
	Algorithm  string
	Charset    string
	DigestURI  string
	AuthID     string
	ServerType string
}

var DefaultGenerator sasl.Generator

func newDigest(opts *Options) *digest {
	if opts.Generator == nil {
		opts.Generator = DefaultGenerator
	}

	return &digest{challenge: newChallenge(opts), response: newResponse(opts)}
}

func NewServer(opts *Options) *Server {
	return (*Server)(newDigest(opts))
}

func NewClient(opts *Options) *Client {
	return (*Client)(newDigest(opts))
}

// Algorithm, Nonce, Realm, Charset and QOP will be set from challenge message
func NewClientFromChallenge(chal []byte, opts *Options) (*Client, error) {
	m := &digest{challenge: &challenge{}, response: newResponse(opts)}

	if err := m.challenge.parseChallenge(chal); err != nil {
		return err
	}
	m.response.nonce = m.challenge.nonce
	m.response.charset = m.challenge.charset
	if len(m.challenge.realms) > 0 {
		m.response.realm = m.challenge.realms[0]
	}
	if len(m.challenge.qop) > 0 {
		m.response.qop = m.challenge.qop[0]
	}

	return (*Client)(m)
}

func (m *Server) Challenge() []byte {
	return m.challenge.challenge()
}

func (m *Server) AuthID() string {
	if len(m.response.auth_id) > 0 {
		return string(m.response.auth_id)
	}
	return string(m.response.username)
}

func (m *Server) UserName() string {
	return string(m.response.username)
}

func (m *Client) Response(username, password string) []byte {
	m.response.HashPassword([]byte(password))
	return m.response.response([]byte(username), m.challenge)
}

func (m *Client) ResponseHashed(username string, password []byte) []byte {
	m.response.SetPasswordHash(password)
	return m.response.response([]byte(username), m.challenge)
}

func (m *Server) Final() []byte {
	if m.response.ok {
		return sasl.MakeKeyValue([]byte("rspauth"), m.response.responseAuth())
	}
	return []byte{}
}

func (m *Server) Validate(password string) error {
	m.response.HashPassword([]byte(password))
	return m.response.validate(m.challenge)
}

func (m *Server) ValidateHashed(password []byte) error {
	m.response.SetPasswordHash(password)
	return m.response.validate(m.challenge)
}

func (m *Server) ParseResponse(response []byte) error {
	return m.response.parseResponse(response, m.challenge)
}
