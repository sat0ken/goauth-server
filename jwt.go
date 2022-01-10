package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
)

func readPrivateKey() (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile("private-key.pem")
	if err != nil {
		return nil, err
	}
	keyblock, _ := pem.Decode(data)
	if keyblock == nil {
		return nil, fmt.Errorf("invalid private key data")
	}
	if keyblock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key type : %s", keyblock.Type)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyblock.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func makeHeaderPayload() string {
	var header = []byte(`{"alg":"RS256","kid": "12345678","typ":"JWT"}`)
	var payload = Payload{
		Iss:        "https://oreore.oidc.com",
		Azp:        clientInfo.id,
		Aud:        clientInfo.id,
		Sub:        user.sub,
		AtHash:     "PRzSZsEPQVqzY8xyB2ls5A",
		Nonce:      "abc",
		Name:       user.name_ja,
		GivenName:  user.given_name,
		FamilyName: user.family_name,
		Locale:     user.locale,
		Iat:        time.Now().Unix(),
		Exp:        time.Now().Unix() + ACCESS_TOKEN_DURATION,
	}
	payload_json, _ := json.Marshal(payload)
	b64header := base64.RawURLEncoding.EncodeToString(header)
	b64payload := base64.RawURLEncoding.EncodeToString(payload_json)

	return fmt.Sprintf("%s.%s", b64header, b64payload)
}

func makeJWT() (string, error) {
	jwtString := makeHeaderPayload()

	privateKey, err := readPrivateKey()
	if err != nil {
		return "", err
	}
	err = privateKey.Validate()
	if err != nil {
		return "", fmt.Errorf("private key validate err : %s", err)
	}
	hasher := sha256.New()
	hasher.Write([]byte(jwtString))
	tokenHash := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, tokenHash)
	if err != nil {
		return "", fmt.Errorf("sign by private key is err : %s", err)
	}
	enc := base64.RawURLEncoding.EncodeToString(signature)
	//fmt.Printf("%s.%s", jwtString, enc)
	return fmt.Sprintf("%s.%s", jwtString, enc), nil
}

func makeJWK() []byte {

	data, _ := ioutil.ReadFile("public-key.pem")
	keyset, _ := jwk.ParseKey(data, jwk.WithPEM(true))

	keyset.Set(jwk.KeyIDKey, "12345678")
	keyset.Set(jwk.AlgorithmKey, "RS256")
	keyset.Set(jwk.KeyUsageKey, "sig")

	jwk := map[string]interface{}{
		"keys": []interface{}{keyset},
	}
	buf, _ := json.MarshalIndent(jwk, "", "  ")
	return buf

}
