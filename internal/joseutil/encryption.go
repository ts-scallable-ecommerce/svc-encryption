package joseutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

// Encrypt encrypts the given payload as a compact JWE using ECDH-ES with A256GCM.
// If sign is true and signingKey is provided, the payload is first signed using
// EdDSA and the resulting compact JWS is encrypted.
func Encrypt(payload []byte, pub *ecdsa.PublicKey, signingKey ed25519.PrivateKey, sign bool) (string, error) {
	if pub == nil {
		return "", errors.New("recipient public key is required")
	}

	content := payload
	if sign {
		if len(signingKey) == 0 {
			return "", errors.New("signing requested but no Ed25519 private key provided")
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: signingKey}, (&jose.SignerOptions{}).WithType("JOSE"))
		if err != nil {
			return "", fmt.Errorf("create signer: %w", err)
		}
		jws, err := signer.Sign(payload)
		if err != nil {
			return "", fmt.Errorf("sign payload: %w", err)
		}
		compact, err := jws.CompactSerialize()
		if err != nil {
			return "", fmt.Errorf("serialize jws: %w", err)
		}
		content = []byte(compact)
	}

	encOpts := (&jose.EncrypterOptions{}).WithType("JWE")
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, encOpts)
	if err != nil {
		return "", fmt.Errorf("create encrypter: %w", err)
	}

	jwe, err := enc.Encrypt(content)
	if err != nil {
		return "", fmt.Errorf("encrypt payload: %w", err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize jwe: %w", err)
	}
	return compact, nil
}

// Decrypt decrypts a compact JWE string using the provided EC private key.
// If verify is true, the decrypted payload is treated as a compact JWS that is
// verified using the provided Ed25519 public key.
func Decrypt(compact string, priv *ecdsa.PrivateKey, verifyKey ed25519.PublicKey, verify bool) ([]byte, bool, error) {
	if priv == nil {
		return nil, false, errors.New("private key is required")
	}
	obj, err := jose.ParseEncrypted(compact)
	if err != nil {
		return nil, false, fmt.Errorf("parse jwe: %w", err)
	}
	decrypted, err := obj.Decrypt(priv)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt jwe: %w", err)
	}

	if verify {
		if len(verifyKey) == 0 {
			return nil, false, errors.New("verification requested but no Ed25519 public key provided")
		}
		jws, err := jose.ParseSigned(string(decrypted))
		if err != nil {
			return nil, false, fmt.Errorf("parse jws: %w", err)
		}
		payload, err := jws.Verify(verifyKey)
		if err != nil {
			return nil, false, fmt.Errorf("verify jws: %w", err)
		}
		return payload, true, nil
	}

	return decrypted, false, nil
}
