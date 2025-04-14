package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type token struct {
	header  map[string]string
	payload map[string]string
	signer  signer
}

type signer interface {
	Alg() string
	Sign(headerB64 string, payloadB64 string) string
}

func New(s signer) token {
	t := token{
		header:  make(map[string]string),
		payload: make(map[string]string),
		signer:  s,
	}
	t.header["typ"] = "JWT"
	t.header["alg"] = s.Alg()
	return t
}

func Verify(tokenB64 string, s signer) (bool, error) {
	split := strings.Split(tokenB64, ".")
	if len(split) != 3 {
		return false, fmt.Errorf("invalid token structure")
	}
	validSign := s.Sign(split[0], split[1])
	return split[2] == validSign, nil
}

func toB64String(data map[string]string) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", nil
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (t *token) Generete() (string, error) {
	var err error
	headerB64, err := toB64String(t.header)
	if err != nil {
		return "", err
	}
	payloadB64, err := toB64String(t.payload)
	if err != nil {
		return "", err
	}
	signatureB64 := t.signer.Sign(headerB64, payloadB64)
	return fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64), nil
}

func (t *token) SetClaim(key string, value string) {
	t.payload[key] = value
}

func (t *token) Claim(key string) (string, bool) {
	claim, ok := t.payload[key]
	if !ok {
		return "", false
	}

	return claim, true
}
