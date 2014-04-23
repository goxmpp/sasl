package scram

import (
	"crypto/rand"
	mrand "math/rand"
	"time"
)

const (
	SALT_BYTES     = 32
	NONCE_BYTES    = 20
	MIN_ITERATIONS = 4096
	MAX_ITERATIONS = 10000
)

type Generator interface {
	// Method used in CNonce and Nonce generation
	GetNonce() []byte
	// Salt derivation function
	GetSalt() []byte
	// Iterations count derivation function
	GetIterations() int
}

type Generators struct{}

// Generate nonce and returns it as string
func (g Generators) GetNonce() []byte {
	nonce := make([]byte, NONCE_BYTES)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return base64ToBytes(nonce)
}

// Generates Salt and returns is as slice of bytes
func (g Generators) GetSalt() []byte {
	salt := make([]byte, SALT_BYTES)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

// Generates Iterations count. RFC5802 requires minimum number of iterations to be at least 4096 to be secure
func (g Generators) GetIterations() int {
	mrand.Seed(time.Now().UnixNano())
	return MIN_ITERATIONS + mrand.Intn(MAX_ITERATIONS-MIN_ITERATIONS)
}
