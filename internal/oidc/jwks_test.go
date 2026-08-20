package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/chr0nzz/gatekeeper/internal/db"
	jose "github.com/go-jose/go-jose/v4"
)

func TestKeySetServesOnlyPublicKeyMaterial(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(filepath.Join(t.TempDir(), "jwks.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer conn.Close()

	s := NewStorage(conn, "https://auth.example.com")
	if err := s.EnsureSigningKey(ctx); err != nil {
		t.Fatalf("ensure signing key: %v", err)
	}
	if _, err := s.RotateSigningKeyIfDue(ctx); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	keys, err := s.KeySet(ctx)
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("keyset is empty")
	}

	for _, k := range keys {
		if _, ok := k.Key().(*rsa.PublicKey); !ok {
			t.Fatalf("KeySet key %s exposes a %T, want *rsa.PublicKey", k.ID(), k.Key())
		}
		jwk := jose.JSONWebKey{Key: k.Key(), KeyID: k.ID(), Algorithm: string(k.Algorithm()), Use: k.Use()}
		raw, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal jwk %s: %v", k.ID(), err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("unmarshal jwk %s: %v", k.ID(), err)
		}
		for _, secret := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
			if _, present := fields[secret]; present {
				t.Errorf("published JWKS for key %s contains private field %q", k.ID(), secret)
			}
		}
		for _, want := range []string{"kty", "n", "e", "kid"} {
			if _, present := fields[want]; !present {
				t.Errorf("published JWKS for key %s is missing %q", k.ID(), want)
			}
		}
	}
}

func TestSigningKeyStillCarriesThePrivateKeyForSigning(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(filepath.Join(t.TempDir(), "sign.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer conn.Close()

	s := NewStorage(conn, "https://auth.example.com")
	if err := s.EnsureSigningKey(ctx); err != nil {
		t.Fatalf("ensure signing key: %v", err)
	}
	sk, err := s.SigningKey(ctx)
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	if _, ok := sk.Key().(*rsa.PrivateKey); !ok {
		t.Fatalf("SigningKey returns a %T, the signer needs *rsa.PrivateKey", sk.Key())
	}
}
