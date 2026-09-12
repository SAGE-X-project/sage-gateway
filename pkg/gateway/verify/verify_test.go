package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/core/rfc9421"

	"github.com/sage-x-project/sage-gateway/pkg/gateway/resolve"
	"github.com/sage-x-project/sage-gateway/pkg/gateway/sign"
	"github.com/sage-x-project/sage-gateway/pkg/gateway/verify"
)

const (
	didA = "did:sage:ethereum:0x1111111111111111111111111111111111111111"
	didB = "did:sage:ethereum:0x2222222222222222222222222222222222222222"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// upstream echoes the JSON-RPC body and records the verified DID header.
func upstream(t *testing.T, sawDID *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*sawDID = r.Header.Get(verify.HeaderVerifiedDID)
		if r.Header.Get("Signature") != "" {
			t.Error("upstream received the caller's Signature header")
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"result":{"echo":` + string(body) + `}}`))
	}))
}

func TestSignedRequestPassesAndResponseIsVerified(t *testing.T) {
	pubA, privA := newKey(t)
	pubB, privB := newKey(t)
	var sawDID string
	up := upstream(t, &sawDID)
	defer up.Close()
	upURL, _ := url.Parse(up.URL)

	trusted, err := resolve.ParseStatic(didA + "=" + hex.EncodeToString(pubA) + ";" + didB + "=0x" + hex.EncodeToString(pubB))
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(verify.ReverseProxy(upURL, verify.Options{
		Resolver: trusted, Signer: privB, KeyID: didB + "#key-1", Algorithm: "ed25519",
	}))
	defer gw.Close()
	gwURL, _ := url.Parse(gw.URL)

	client := &http.Client{Transport: &sign.Transport{
		Signer: privA, DID: didA, Algorithm: "ed25519",
		PeerResolver: trusted, PeerDID: didB,
	}}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo"}}`
	req, _ := http.NewRequest(http.MethodPost, gw.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(got), `"echo":`+body) {
		t.Fatalf("status %d body %s", resp.StatusCode, got)
	}
	if sawDID != didA {
		t.Fatalf("upstream saw DID %q", sawDID)
	}
	if resp.Header.Get("Signature-Input") == "" || !strings.Contains(resp.Header.Get("Signature-Input"), `"@method";req`) {
		t.Fatalf("response not bound to the request: %s", resp.Header.Get("Signature-Input"))
	}
	_ = gwURL
}

func TestUnsignedUnknownAndReplayedRequestsAreRejected(t *testing.T) {
	pubA, privA := newKey(t)
	_, privC := newKey(t)
	var sawDID string
	up := upstream(t, &sawDID)
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	trusted := resolve.NewStatic()
	trusted.Add(didA, pubA)
	gw := httptest.NewServer(verify.ReverseProxy(upURL, verify.Options{Resolver: trusted}))
	defer gw.Close()

	// Unsigned.
	resp, err := http.Post(gw.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: status %d", resp.StatusCode)
	}

	// Signed by an agent the gateway does not know.
	unknown := &http.Client{Transport: &sign.Transport{Signer: privC, DID: didB, Algorithm: "ed25519"}}
	resp, err = unknown.Post(gw.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown agent: status %d", resp.StatusCode)
	}

	// A valid request replayed byte for byte.
	fixed := time.Now()
	tr := &sign.Transport{Signer: privA, DID: didA, Algorithm: "ed25519", Now: func() time.Time { return fixed }}
	req, _ := http.NewRequest(http.MethodPost, gw.URL+"/mcp", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	signed := req.Clone(req.Context())
	signed.Body = io.NopCloser(strings.NewReader(`{"a":1}`))
	resp, err = tr.RoundTrip(signed)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first: status %d", resp.StatusCode)
	}
	// Re-send the exact signed request (same nonce) through a plain transport.
	replay := signed.Clone(signed.Context())
	replay.Body = io.NopCloser(strings.NewReader(`{"a":1}`))
	resp, err = http.DefaultTransport.RoundTrip(replay)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: status %d", resp.StatusCode)
	}
}

func TestAuthorityBinding(t *testing.T) {
	pubA, privA := newKey(t)
	var sawDID string
	up := upstream(t, &sawDID)
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	trusted := resolve.NewStatic()
	trusted.Add(didA, pubA)
	gw := httptest.NewServer(verify.ReverseProxy(upURL, verify.Options{Resolver: trusted, Authorities: []string{"agent-b.example"}}))
	defer gw.Close()
	client := &http.Client{Transport: &sign.Transport{Signer: privA, DID: didA, Algorithm: "ed25519"}}
	resp, err := client.Post(gw.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong authority accepted: status %d", resp.StatusCode)
	}
}

func TestVerifierRejectsOversizedBody(t *testing.T) {
	pubA, privA := newKey(t)
	var sawDID string
	up := upstream(t, &sawDID)
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	trusted := resolve.NewStatic()
	trusted.Add(didA, pubA)
	gw := httptest.NewServer(verify.ReverseProxy(upURL, verify.Options{Resolver: trusted, MaxBodyBytes: 16}))
	defer gw.Close()
	client := &http.Client{Transport: &sign.Transport{Signer: privA, DID: didA, Algorithm: "ed25519"}}
	resp, err := client.Post(gw.URL+"/mcp", "application/json", strings.NewReader(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("oversized body accepted: status %d", resp.StatusCode)
	}
	_ = rfc9421.DefaultMaxClockSkew
}
