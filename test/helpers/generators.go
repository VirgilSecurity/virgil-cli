package helpers

import (
	"crypto/rand"
	"encoding/hex"
)

const (
	DisposableEmailOperator = "@mailinator.com"
)

func GenerateEmail() string {
	return GenerateString() + DisposableEmailOperator
}

func GeneratePassowrd() string {
	return GenerateString()[:29]
}

func GenerateString() string {
	randBytes := make([]byte, 32)
	_, _ = rand.Read(randBytes)
	return hex.EncodeToString(randBytes)
}
