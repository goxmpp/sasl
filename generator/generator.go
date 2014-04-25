package generator

import (
	"crypto/rand"
	mrand "math/rand"
	"time"

	"github.com/azhavnerchik/sasl/util"
)

const (
	MIN_ITERATIONS = 4096
	MAX_ITERATIONS = 10000
)

type NonceGenerator interface {
	// Method used in CNonce and Nonce generation
	GetNonce(int) []byte
}

type SaltGenerator interface {
	NonceGenerator
	// Salt derivation function
	GetSalt(int) []byte
	// Iterations count derivation function
	GetIterations() int
}

type Generator struct{}

// Generate nonce and returns it as string
func (g Generator) GetNonce(size int) []byte {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return util.Base64ToBytes(nonce)
}

// Generates Salt and returns is as slice of bytes
func (g Generator) GetSalt(size int) []byte {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

// Generates Iterations count. RFC5802 requires minimum number of iterations to be at least 4096 to be secure
func (g Generator) GetIterations() int {
	mrand.Seed(time.Now().UnixNano())
	return MIN_ITERATIONS + mrand.Intn(MAX_ITERATIONS-MIN_ITERATIONS)
}
