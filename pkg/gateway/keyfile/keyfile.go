// Package keyfile loads an agent's signing key from the files written by
// sage-crypto (JWK or PEM, optionally wrapped in the sage-crypto envelope)
// or from a sage file key storage directory.
package keyfile

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"

	sagecrypto "github.com/sage-x-project/sage/pkg/agent/crypto"
	"github.com/sage-x-project/sage/pkg/agent/crypto/formats"
	"github.com/sage-x-project/sage/pkg/agent/crypto/keys"
	"github.com/sage-x-project/sage/pkg/agent/crypto/storage"
)

// Source says where the key comes from. Exactly one of File or
// StorageDir+KeyID must be set.
type Source struct {
	File       string // path to a JWK or PEM file
	Format     string // "jwk" (default) or "pem"
	StorageDir string // sage file key storage directory
	KeyID      string // key id inside StorageDir
}

type wrapper struct {
	PrivateKey json.RawMessage `json:"private_key"`
}

// Load returns the key pair described by src.
func Load(src Source) (sagecrypto.KeyPair, error) {
	if src.StorageDir != "" && src.KeyID != "" {
		store, err := storage.NewFileKeyStorage(src.StorageDir)
		if err != nil {
			return nil, fmt.Errorf("open key storage: %w", err)
		}
		return store.Load(src.KeyID)
	}
	if src.File == "" {
		return nil, fmt.Errorf("no key source: set File (with Format) or StorageDir and KeyID")
	}
	data, err := os.ReadFile(src.File) // #nosec G304 -- path supplied by the operator
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var importer sagecrypto.KeyImporter
	var format sagecrypto.KeyFormat
	switch src.Format {
	case "", "jwk":
		importer, format = formats.NewJWKImporter(), sagecrypto.KeyFormatJWK
		var w wrapper
		if json.Unmarshal(data, &w) == nil && len(w.PrivateKey) > 0 {
			data = w.PrivateKey
		}
	case "pem":
		importer, format = formats.NewPEMImporter(), sagecrypto.KeyFormatPEM
	default:
		return nil, fmt.Errorf("unsupported key format %q (jwk or pem)", src.Format)
	}
	kp, err := importer.Import(data, format)
	if err != nil {
		return nil, fmt.Errorf("import %s key from %s: %w", format, src.File, err)
	}
	return kp, nil
}

// Signer returns the private key as a crypto.Signer and the RFC 9421
// algorithm identifier SAGE uses for it.
func Signer(kp sagecrypto.KeyPair) (crypto.Signer, string, error) {
	signer, ok := kp.PrivateKey().(crypto.Signer)
	if !ok {
		return nil, "", fmt.Errorf("key type %s is not a signing key", kp.Type())
	}
	alg, err := Algorithm(kp)
	if err != nil {
		return nil, "", err
	}
	return signer, alg, nil
}

// Algorithm maps the key type to the RFC 9421 alg parameter (sage-spec §1.3).
func Algorithm(kp sagecrypto.KeyPair) (string, error) {
	switch kp.Type() {
	case sagecrypto.KeyTypeEd25519:
		return "ed25519", nil
	case sagecrypto.KeyTypeSecp256k1:
		return "es256k", nil
	case sagecrypto.KeyTypeP256:
		return "ecdsa-p256-sha256", nil
	case sagecrypto.KeyTypeRSA:
		return "rsa-pss-sha256", nil
	}
	return "", fmt.Errorf("no RFC 9421 algorithm for key type %s", kp.Type())
}

// KeyID returns keys.KeyID of the public key, for logging.
func KeyID(kp sagecrypto.KeyPair) string {
	return keys.KeyID(publicBytes(kp))
}

func publicBytes(kp sagecrypto.KeyPair) []byte {
	if b, ok := kp.PublicKey().([]byte); ok {
		return b
	}
	if s, ok := kp.PublicKey().(interface{ Bytes() []byte }); ok {
		return s.Bytes()
	}
	return nil
}
