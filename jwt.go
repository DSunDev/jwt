package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type claims map[string]string

type signer interface {
	Alg() string
	Sign(headerB64 string, payloadB64 string) string
}

func NewClaims() claims {
	return make(claims)
}

func Generate(claims claims, signer signer) (string, error) {
	header := make(map[string]string)
	header["typ"] = "JWT"
	header["alg"] = signer.Alg()
	headerB64, err := mapToB64Json(header)
	if err != nil {
		return "", err
	}

	payloadB64, err := mapToB64Json(map[string]string(claims))
	if err != nil {
		return "", err
	}

	signatureB64 := signer.Sign(headerB64, payloadB64)
	return fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64), nil
}

func Verify(tokenB64 string, signer signer) (bool, error) {
	split := strings.Split(tokenB64, ".")
	if len(split) != 3 {
		return false, fmt.Errorf("invalid token structure")
	}
	return split[2] == signer.Sign(split[0], split[1]), nil
}

func mapToB64Json(data map[string]string) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", nil
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
