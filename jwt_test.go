package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type signerMock struct{}

func (s signerMock) Alg() string {
	return "MOCK"
}

func (s signerMock) Sign(headerB64 string, payloadB64 string) string {
	return headerB64 + payloadB64
}

func creteToken(signer signerMock) (string, error) {
	claims := NewClaims()
	claims["iss"] = "test"
	token, err := Generate(claims, signer)
	if err != nil {
		return "", err
	}
	return token, nil
}

func decodeHeader(token string) (map[string]string, error) {
	split := strings.Split(token, ".")
	bytes, err := base64.RawURLEncoding.DecodeString(split[0])
	if err != nil {
		return nil, err
	}

	var header map[string]string
	err = json.Unmarshal(bytes, &header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func changeClaim(key string, value string, token string) (changedToken string, err error) {
	split := strings.Split(token, ".")
	bytes, err := base64.RawURLEncoding.DecodeString(split[1])
	if err != nil {
		return "", err
	}

	var claims claims
	err = json.Unmarshal(bytes, &claims)
	if err != nil {
		return "", err
	}

	claims[key] = value
	split[1], err = mapToB64Json(claims)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s.%s", split[0], split[1], split[2]), nil
}

func TestTokenStructure(t *testing.T) {
	signer := signerMock{}
	token, err := creteToken(signer)
	if err != nil {
		t.Error(err)
	}

	split := strings.Split(token, ".")
	if len(split) != 3 {
		t.Errorf("token must consist of three parts in the format: header.payload.signature (%s)", token)
	}
}

func TestHeader(t *testing.T) {
	signer := signerMock{}
	token, err := creteToken(signer)
	if err != nil {
		t.Error(err)
	}

	tests := []struct {
		key, value string
	}{
		{"typ", "JWT"},
		{"alg", signer.Alg()},
	}

	for _, tv := range tests {
		t.Run(tv.key, func(t *testing.T) {
			header, err := decodeHeader(token)
			if err != nil {
				t.Error(err)
			}

			value, ok := header[tv.key]
			if !ok {
				t.Errorf("\"%s\" field not exist", tv.key)
			}
			if value != tv.value {
				t.Errorf("\"%s\" invalid value (%s)", tv.key, value)
			}
		})
	}
}

func TestVerified(t *testing.T) {
	signer := signerMock{}
	token, err := creteToken(signer)
	if err != nil {
		t.Error(err)
	}
	success, err := Verify(token, signer)
	if err != nil {
		t.Error(err)
	}
	if !success {
		t.Error("verification faild")
	}
}

func TestNotVerified(t *testing.T) {
	signer := signerMock{}
	token, err := creteToken(signer)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(token)

	token, err = changeClaim("iss", "invalid", token)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(token)

	success, err := Verify(token, signer)
	if err != nil {
		t.Error(err)
	}
	if success {
		t.Error("verification faild")
	}
}
