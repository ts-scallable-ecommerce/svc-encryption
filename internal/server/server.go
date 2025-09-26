package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"

	"svc-encryption/internal/joseutil"
)

// Config controls the HTTP service.
type Config struct {
	ListenAddr        string
	ECPublicPath      string
	ECPrivatePath     string
	SigningPrivateKey string
	SigningPublicKey  string
}

// Server exposes HTTP endpoints for encrypting and decrypting payloads.
type Server struct {
	cfg      Config
	ecPub    *ecdsa.PublicKey
	ecPriv   *ecdsa.PrivateKey
	signPriv ed25519.PrivateKey
	signPub  ed25519.PublicKey
	app      *fiber.App
}

// New initializes the server.
func New(cfg Config) (*Server, error) {
	if cfg.ECPublicPath == "" || cfg.ECPrivatePath == "" {
		return nil, errors.New("EC public and private key paths are required")
	}
	pub, err := joseutil.LoadECPublicKey(cfg.ECPublicPath)
	if err != nil {
		return nil, err
	}
	priv, err := joseutil.LoadECPrivateKey(cfg.ECPrivatePath)
	if err != nil {
		return nil, err
	}
	signPriv, err := joseutil.LoadEd25519PrivateKey(cfg.SigningPrivateKey)
	if err != nil {
		return nil, err
	}
	signPub, err := joseutil.LoadEd25519PublicKey(cfg.SigningPublicKey)
	if err != nil {
		return nil, err
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(logger.New(logger.Config{Format: "${method} ${path} -> ${status}\n"}))
	s := &Server{cfg: cfg, ecPub: pub, ecPriv: priv, signPriv: signPriv, signPub: signPub, app: app}
	app.Get("/healthz", s.handleHealth)
	app.Post("/encrypt", s.handleEncrypt)
	app.Post("/decrypt", s.handleDecrypt)
	return s, nil
}

// Start begins listening for HTTP traffic.
func (s *Server) Start() error {
	listenAddr := s.cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	return s.app.Listen(listenAddr)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.app.ShutdownWithContext(ctx)
}

func (s *Server) handleHealth(c *fiber.Ctx) error {
	return c.SendString("ok")
}

type encryptRequest struct {
	Plaintext         string `json:"plaintext"`
	PlaintextEncoding string `json:"plaintext_encoding,omitempty"`
	Sign              bool   `json:"sign,omitempty"`
}

type encryptResponse struct {
	JWE string `json:"jwe"`
}

func (s *Server) handleEncrypt(c *fiber.Ctx) error {
	var req encryptRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
	}
	if req.Plaintext == "" {
		return fiber.NewError(fiber.StatusBadRequest, "plaintext is required")
	}

	data, err := decodePayload(req.Plaintext, req.PlaintextEncoding)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	token, err := joseutil.Encrypt(data, s.ecPub, s.signPriv, req.Sign)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(encryptResponse{JWE: token})
}

type decryptRequest struct {
	JWE             string `json:"jwe"`
	VerifySignature bool   `json:"verify_signature,omitempty"`
	OutputEncoding  string `json:"output_encoding,omitempty"`
}

type decryptResponse struct {
	Plaintext         string `json:"plaintext"`
	Encoding          string `json:"encoding"`
	SignatureVerified bool   `json:"signature_verified"`
}

func (s *Server) handleDecrypt(c *fiber.Ctx) error {
	var req decryptRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
	}
	if req.JWE == "" {
		return fiber.NewError(fiber.StatusBadRequest, "jwe is required")
	}

	payload, verified, err := joseutil.Decrypt(req.JWE, s.ecPriv, s.signPub, req.VerifySignature)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	encoding := req.OutputEncoding
	if encoding == "" {
		encoding = "base64"
	}
	var plaintext string
	switch encoding {
	case "base64":
		plaintext = base64.StdEncoding.EncodeToString(payload)
	case "utf-8", "utf8":
		plaintext = string(payload)
	default:
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("unsupported output_encoding: %s", encoding))
	}

	return c.JSON(decryptResponse{Plaintext: plaintext, Encoding: encoding, SignatureVerified: verified})
}

func decodePayload(value, encoding string) ([]byte, error) {
	if encoding == "" || encoding == "base64" {
		data, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode base64 plaintext: %w", err)
		}
		return data, nil
	}
	if encoding == "utf-8" || encoding == "utf8" {
		return []byte(value), nil
	}
	return nil, fmt.Errorf("unsupported plaintext_encoding: %s", encoding)
}
