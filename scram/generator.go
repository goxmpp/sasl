package scram

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"time"
)

const (
	SALT_BYTES     = 32
	NONCE_BYTES    = 20
	MIN_ITERATIONS = 4096
	MAX_ITERATIONS = 10000
)

type Generators struct{}

func (g Generators) GetNonce() string {
	nonce := make([]byte, NONCE_BYTES)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", nonce)
}

func (g Generators) GetSalt() []byte {
	salt := make([]byte, SALT_BYTES)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

func (g Generators) GetIterations() int {
	mrand.Seed(time.Now().UnixNano())
	return MIN_ITERATIONS + mrand.Intn(MAX_ITERATIONS-MIN_ITERATIONS)
}
