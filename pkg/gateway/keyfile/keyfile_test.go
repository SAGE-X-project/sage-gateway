package keyfile

import (
	"os"
	"path/filepath"
	"testing"

	sagecrypto "github.com/sage-x-project/sage/pkg/agent/crypto"
	"github.com/sage-x-project/sage/pkg/agent/crypto/formats"
	"github.com/sage-x-project/sage/pkg/agent/crypto/keys"
)

func TestLoadJWKAndPEM(t *testing.T) {
	dir := t.TempDir()
	kp, err := keys.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := formats.NewJWKExporter().Export(kp, sagecrypto.KeyFormatJWK)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := formats.NewPEMExporter().Export(kp, sagecrypto.KeyFormatPEM)
	if err != nil {
		t.Fatal(err)
	}
	jwkPath := filepath.Join(dir, "a.jwk")
	pemPath := filepath.Join(dir, "a.pem")
	wrapped := filepath.Join(dir, "wrapped.json")
	_ = os.WriteFile(jwkPath, jwk, 0o600)
	_ = os.WriteFile(pemPath, pem, 0o600)
	_ = os.WriteFile(wrapped, []byte(`{"private_key":`+string(jwk)+`,"key_id":"x","key_type":"Ed25519"}`), 0o600)

	for _, src := range []Source{{File: jwkPath}, {File: wrapped, Format: "jwk"}, {File: pemPath, Format: "pem"}} {
		got, err := Load(src)
		if err != nil {
			t.Fatalf("%+v: %v", src, err)
		}
		signer, alg, err := Signer(got)
		if err != nil || signer == nil || alg != "ed25519" {
			t.Fatalf("%+v: signer %v alg %q err %v", src, signer, alg, err)
		}
		if KeyID(got) != KeyID(kp) {
			t.Fatalf("%+v: key id mismatch", src)
		}
	}
	if _, err := Load(Source{}); err == nil {
		t.Fatal("empty source accepted")
	}
	if _, err := Load(Source{File: jwkPath, Format: "der"}); err == nil {
		t.Fatal("unknown format accepted")
	}
}
