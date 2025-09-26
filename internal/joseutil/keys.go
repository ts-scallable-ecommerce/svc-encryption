package joseutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

var (
	errNoPEMBlock = errors.New("no PEM block found")
)

// LoadECPrivateKey reads a P-256 EC private key from a PEM-encoded file.
func LoadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read EC private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("read EC private key: %w", errNoPEMBlock)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// try PKCS8
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parse EC private key: expected ecdsa key, got %T", pkcs8Key)
		}
		return ecKey, nil
	}
	return key, nil
}

// LoadECPublicKey reads a P-256 EC public key from a PEM-encoded file.
func LoadECPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read EC public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("read EC public key: %w", errNoPEMBlock)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC public key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parse EC public key: expected ecdsa key, got %T", pubAny)
	}
	return pub, nil
}

// LoadEd25519PrivateKey reads an Ed25519 private key from a PEM file.
func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Ed25519 private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("read Ed25519 private key: %w", errNoPEMBlock)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 private key: %w", err)
	}
	pk, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parse Ed25519 private key: expected ed25519 key, got %T", parsed)
	}
	return pk, nil
}

// LoadEd25519PublicKey reads an Ed25519 public key from a PEM file.
func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Ed25519 public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("read Ed25519 public key: %w", errNoPEMBlock)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 public key: %w", err)
	}
	pk, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parse Ed25519 public key: expected ed25519 key, got %T", parsed)
	}
	return pk, nil
}

// GenerateECKeyPair generates a new P-256 EC key pair and writes it to disk.
func GenerateECKeyPair(privatePath, publicPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate EC key: %w", err)
	}

	derPriv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	if err := writePEM(privatePath, "EC PRIVATE KEY", derPriv, 0600); err != nil {
		return err
	}

	derPub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal EC public key: %w", err)
	}
	if err := writePEM(publicPath, "PUBLIC KEY", derPub, 0644); err != nil {
		return err
	}
	return nil
}

// GenerateEd25519KeyPair generates an Ed25519 key pair and writes it to disk.
func GenerateEd25519KeyPair(privatePath, publicPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Ed25519 key: %w", err)
	}

	derPriv, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal Ed25519 private key: %w", err)
	}
	if err := writePEM(privatePath, "PRIVATE KEY", derPriv, 0600); err != nil {
		return err
	}

	derPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal Ed25519 public key: %w", err)
	}
	if err := writePEM(publicPath, "PUBLIC KEY", derPub, 0644); err != nil {
		return err
	}
	return nil
}

func writePEM(path, typ string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("path must not be empty")
	}
	if err := ioutil.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data}), perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
