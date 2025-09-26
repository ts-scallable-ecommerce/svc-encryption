# svc-encryption

`svc-encryption` is a JOSE-based encryption service and toolkit written in Go. It exposes HTTP APIs and CLI commands for encrypting and decrypting payloads using forward-secret JWE (ECDH-ES + A256GCM) and optional EdDSA signatures.

## Features

- **HTTP service** with `/encrypt` and `/decrypt` endpoints backed by EC (P-256) key material.
- **Command line utilities** to encrypt/decrypt payloads offline and to generate fresh key pairs.
- **Forward secrecy** via ECDH-ES with ephemeral keys per-message.
- **Optional authenticity** using nested EdDSA JWS signatures.

## Installation

Build the CLI binary:

```bash
go build ./cmd/svc-encryption
```

## Key Generation

Create a directory and generate the required EC keys (and optional EdDSA signing keys):

```bash
./svc-encryption gen-keys --out-dir ./keys --with-signing
```

This command produces:

- `ec_private.pem` / `ec_public.pem` – P-256 key pair used for decrypt/encrypt.
- `signing_private.pem` / `signing_public.pem` – Ed25519 keys for signing and verification (only when `--with-signing` is supplied).

You can override individual output paths with the `--ec-private`, `--ec-public`, `--signing-private`, and `--signing-public` flags.

## Running the Service

Start the HTTP API by providing the key paths:

```bash
./svc-encryption serve \
  --listen :8080 \
  --ec-public ./keys/ec_public.pem \
  --ec-private ./keys/ec_private.pem \
  --signing-private ./keys/signing_private.pem \
  --signing-public ./keys/signing_public.pem
```

- The signing keys are optional. When provided, `/encrypt` will sign payloads when the caller sets `"sign": true`, and `/decrypt` can verify nested signatures when `"verify_signature": true`.

### API Overview

#### `POST /encrypt`

Request body:

```json
{
  "plaintext": "<data>",
  "plaintext_encoding": "base64", // or "utf-8"
  "sign": true
}
```

`plaintext` is interpreted as Base64 unless `plaintext_encoding` is `"utf-8"`. When `sign` is true, the service must be configured with a signing private key.

Response:

```json
{
  "jwe": "<compact JWE>"
}
```

#### `POST /decrypt`

Request body:

```json
{
  "jwe": "<compact JWE>",
  "verify_signature": true,
  "output_encoding": "base64" // or "utf-8"
}
```

When `verify_signature` is true, the service must be configured with a signing public key. The decrypted payload is returned either as Base64 (`output_encoding` omitted or `base64`) or UTF-8 text.

Response:

```json
{
  "plaintext": "<payload>",
  "encoding": "base64",
  "signature_verified": true
}
```

## CLI Usage

### Encrypt offline

```bash
echo "super secret" | ./svc-encryption encrypt \
  --ec-public ./keys/ec_public.pem \
  --sign \
  --signing-private ./keys/signing_private.pem \
  > message.jwe
```

### Decrypt offline

```bash
./svc-encryption decrypt \
  --ec-private ./keys/ec_private.pem \
  --verify \
  --signing-public ./keys/signing_public.pem \
  --input message.jwe
```

The decrypted plaintext is printed to stdout. The command also prints whether the signature was verified when `--verify` is supplied.

## Health Check

The service exposes `GET /healthz` which returns `200 OK` with the body `ok`.

## Testing

Run standard Go tests:

```bash
go test ./...
```
