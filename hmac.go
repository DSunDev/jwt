package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type hs256 struct {
	secretKey string
}

func NewHS256(secretKey string) hs256 {
	h := hs256{secretKey: secretKey}
	return h
}

func (h hs256) Alg() string {
	return "HS256"
}

func (h hs256) Sign(headerB64 string, payloadB64 string) string {
	hash := hmac.New(sha256.New, []byte(h.secretKey))
	hash.Write([]byte(fmt.Sprintf("%s.%s", headerB64, payloadB64)))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
