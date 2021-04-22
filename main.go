package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"golang.org/x/crypto/ssh"
)

var template = `{
	"type": {{ toJson .Type }},
	"keyId": {{ toJson .KeyID }},
	"principals": {{ append .Principals .Token.preferred_username | toJson }},
	"extensions": {{ toJson .Extensions }},
	"criticalOptions": {{ toJson .CriticalOptions }}
}`

func main() {
	// JWT token created using:
	// 	step crypto jwk create key.pub key.priv
	// 	echo '{"preferred_username":"foobar"}' | step crypto jwt sign \
	// 		--key key.priv --iss "joe@example.com" --aud "https://example.com"
	//  	--sub mariano@smallstep.com --exp $(date -v+1M +"%s")
	//
	// The token looks like:
	// {
	//   "header": {
	//     "alg": "ES256",
	//     "kid": "uKdIYbdEkPer1H6aMO2lcjq6RHKhdazsYzuJy2NnA60",
	//     "typ": "JWT"
	//   },
	//   "payload": {
	//     "aud": "https://example.com",
	//     "exp": 1619115337,
	//     "iat": 1619115280,
	//     "iss": "joe@example.com",
	//     "jti": "9215c3997ad7f0a0545922f1f496d4348d9c4fc4ea06d59ee4fb0935b87bbc86",
	//     "nbf": 1619115280,
	//     "preferred_username": "foobar",
	//     "sub": "mariano@smallstep.com"
	//   },
	//   "signature": "ldqJX9elhUR-qxjv5U7B09R0xgmGh8khS_jU8rW0a-WJGBtjExShlON3WK41clkOn80iJKMpjbogci8bk25m3w"
	// }
	token := "eyJhbGciOiJFUzI1NiIsImtpZCI6InVLZElZYmRFa1BlcjFINmFNTzJsY2pxNlJIS2hkYXpzWXp1SnkyTm5BNjAiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxNjE5MTE1MzM3LCJpYXQiOjE2MTkxMTUyODAsImlzcyI6ImpvZUBleGFtcGxlLmNvbSIsImp0aSI6IjkyMTVjMzk5N2FkN2YwYTA1NDU5MjJmMWY0OTZkNDM0OGQ5YzRmYzRlYTA2ZDU5ZWU0ZmIwOTM1Yjg3YmJjODYiLCJuYmYiOjE2MTkxMTUyODAsInByZWZlcnJlZF91c2VybmFtZSI6ImZvb2JhciIsInN1YiI6Im1hcmlhbm9Ac21hbGxzdGVwLmNvbSJ9.ldqJX9elhUR-qxjv5U7B09R0xgmGh8khS_jU8rW0a-WJGBtjExShlON3WK41clkOn80iJKMpjbogci8bk25m3w"

	// Certificate Key
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}

	// Certificate signer
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}

	// Template data
	data := sshutil.CreateTemplateData(sshutil.UserCert, "mariano@smallstep.com", []string{"mariano"})
	v, err := unsafeParseSigned(token)
	if err != nil {
		log.Fatal(err)
	}
	data.SetToken(v)

	// Create template
	cert, err := sshutil.NewCertificate(sshutil.CertificateRequest{Key: key}, sshutil.WithTemplate(template, data))
	if err != nil {
		log.Fatal(err)
	}

	// Sign
	sshCert, err := sshutil.CreateCertificate(cert.GetCertificate(), signer)
	if err != nil {
		log.Fatal(err)
	}

	b, err := json.MarshalIndent(sshCert, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
}

func unsafeParseSigned(s string) (map[string]interface{}, error) {
	token, err := jose.ParseSigned(s)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]interface{})
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
