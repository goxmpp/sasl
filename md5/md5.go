package md5

type MD5 struct {
	*challenge
	*response
}

func New(realms []string, alg string) *MD5 {
	return &MD5{challenge: newChallenge(realms, []byte(alg)), response: newResponse()}
}

func (m *MD5) AuthID() string {
	if len(m.response.auth_id) > 0 {
		return string(m.response.auth_id)
	}
	return string(m.response.username)
}

func (m *MD5) UserName() string {
	return string(m.response.username)
}

func (m *MD5) Final() []byte {
	if m.response.ok {
		return []byte("rspauth") // TODO reply something else on failed authentication
	}
	return []byte{}
}

func (m *MD5) Validate(password string) error {
	return m.response.Validate([]byte(password), m.challenge)
}

func (m *MD5) ParseResponse(response []byte) error {
	return m.response.ParseResponse(response, m.challenge)
}
