// Package sign adds SAGE RFC 9421 signatures to outbound HTTP requests
// and, when the peer's key is known, verifies the signed responses.
package sign

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/sage-x-project/sage/pkg/agent/core/rfc9421"

	"github.com/sage-x-project/sage-gateway/pkg/gateway/resolve"
)

// Transport is an http.RoundTripper that signs every request.
type Transport struct {
	Base      http.RoundTripper
	Signer    crypto.Signer
	DID       string // placed in X-SAGE-DID and, with KeyFragment, in keyid
	KeyID     string // keyid parameter; defaults to DID
	Algorithm string // RFC 9421 alg (ed25519, es256k, ecdsa-p256-sha256)
	// Verifier and PeerResolver enable response verification: the response
	// must be signed by the key of PeerDID (or of the DID in its keyid when
	// PeerDID is empty) and bound to the request.
	Verifier     *rfc9421.HTTPVerifier
	PeerResolver resolve.KeyResolver
	PeerDID      string
	// SignatureName defaults to sig1; MaxBodyBytes caps buffered bodies.
	SignatureName string
	MaxBodyBytes  int64
	Now           func() time.Time
}

// Components covered by every signed request (sage-spec §3.3); the
// content-* components are dropped when there is no body.
var Components = []string{`"@method"`, `"@target-uri"`, `"@authority"`, `"content-type"`, `"content-digest"`, `"x-sage-did"`, `"date"`}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Signer == nil || t.DID == "" {
		return nil, fmt.Errorf("sign: Signer and DID are required")
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	verifier := t.Verifier
	if verifier == nil {
		verifier = rfc9421.NewHTTPVerifierWithReplayGuard(nil)
	}
	now := t.Now
	if now == nil {
		now = time.Now
	}
	r := req.Clone(req.Context())
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("sign: read body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Digest", rfc9421.ComputeContentDigest(body))
		if r.Header.Get("Content-Type") == "" {
			r.Header.Set("Content-Type", "application/octet-stream")
		}
	}
	r.Header.Set("X-SAGE-DID", t.DID)
	r.Header.Set("Date", now().UTC().Format(http.TimeFormat))
	covered := Components
	if len(body) == 0 {
		covered = []string{`"@method"`, `"@target-uri"`, `"@authority"`, `"x-sage-did"`, `"date"`}
	}
	keyID := t.KeyID
	if keyID == "" {
		keyID = t.DID
	}
	name := t.SignatureName
	if name == "" {
		name = "sig1"
	}
	params := &rfc9421.SignatureInputParams{
		CoveredComponents: covered,
		KeyID:             keyID,
		Algorithm:         t.Algorithm,
		Created:           now().Unix(),
		Nonce:             uuid.NewString(),
	}
	if err := verifier.SignRequest(r, name, params, t.Signer); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	resp, err := base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if t.PeerResolver == nil {
		return resp, nil
	}
	if err := t.verifyResponse(resp, r, verifier); err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("sign: response verification: %w", err)
	}
	return resp, nil
}

func (t *Transport) verifyResponse(resp *http.Response, req *http.Request, verifier *rfc9421.HTTPVerifier) error {
	inputs, err := rfc9421.ParseSignatureInput(resp.Header.Get("Signature-Input"))
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		return fmt.Errorf("response is not signed")
	}
	var keyID string
	for _, p := range inputs {
		keyID = p.KeyID
		break
	}
	peer := t.PeerDID
	if peer == "" {
		peer = rfc9421.KeyIDDID(keyID)
	}
	pub, err := t.PeerResolver.ResolvePublicKey(req.Context(), peer)
	if err != nil {
		return err
	}
	maxBody := t.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 16 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxBody {
		return fmt.Errorf("response body too large")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	opts := rfc9421.StrictHTTPResponseVerificationOptions()
	opts.ExpectedDID = peer
	if err := verifier.VerifyResponse(resp, req, pub, opts); err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// ForwardProxy returns a handler that accepts unsigned requests from a
// local client, signs them with t, and forwards them to upstream. Use it
// for clients that cannot sign themselves (an MCP client pointed at
// http://127.0.0.1:<port>/).
func ForwardProxy(upstream *url.URL, t *Transport) http.Handler {
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(upstream)
		pr.Out.Host = upstream.Host
	}}
	proxy.Transport = t
	return proxy
}
