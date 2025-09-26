package server

import (
	"encoding/base64"
	"testing"
)

func TestResolveEncryptPayloadJSON(t *testing.T) {
	req := &encryptRequest{JSON: []byte("{\"foo\":\"bar\"}")}
	got, err := resolveEncryptPayload(req)
	if err != nil {
		t.Fatalf("resolveEncryptPayload() error = %v", err)
	}
	want := []byte("{\"foo\":\"bar\"}")
	if string(got) != string(want) {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestResolveEncryptPayloadJSONWhitespace(t *testing.T) {
	req := &encryptRequest{JSON: []byte("  [1,2,3]  ")}
	got, err := resolveEncryptPayload(req)
	if err != nil {
		t.Fatalf("resolveEncryptPayload() error = %v", err)
	}
	want := []byte("[1,2,3]")
	if string(got) != string(want) {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestResolveEncryptPayloadPlaintext(t *testing.T) {
	value := base64.StdEncoding.EncodeToString([]byte("secret"))
	req := &encryptRequest{Plaintext: value}
	got, err := resolveEncryptPayload(req)
	if err != nil {
		t.Fatalf("resolveEncryptPayload() error = %v", err)
	}
	want := []byte("secret")
	if string(got) != string(want) {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestResolveEncryptPayloadErrors(t *testing.T) {
	tests := []struct {
		name string
		req  *encryptRequest
	}{
		{"missing", &encryptRequest{}},
		{"both", &encryptRequest{Plaintext: "test", JSON: []byte("{}")}},
		{"emptyJSON", &encryptRequest{JSON: []byte("   ")}},
		{"invalidEncoding", &encryptRequest{Plaintext: "test", PlaintextEncoding: "unknown"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveEncryptPayload(tc.req)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestResolveEncryptPayloadInvalidJSON(t *testing.T) {
	req := &encryptRequest{JSON: []byte("  {invalid}  ")}
	_, err := resolveEncryptPayload(req)
	if err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
	if err.Error() != "json payload must be valid JSON" {
		t.Fatalf("unexpected error: %v", err)
	}
}
