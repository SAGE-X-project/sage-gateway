// Package verify protects an HTTP service (typically an MCP server) with
// SAGE RFC 9421 verification: every request must carry a valid signature
// from an agent whose key the resolver knows, and responses are signed
// back to the caller when a key is configured.
package verify

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/core/rfc9421"

	"github.com/sage-x-project/sage-gateway/pkg/gateway/resolve"
)

// HeaderVerifiedDID is set on requests handed to the upstream so it can
// authorise by agent identity without re-verifying the signature.
const HeaderVerifiedDID = "X-SAGE-Verified-DID"

// Options configure the middleware.
type Options struct {
	Resolver resolve.KeyResolver
	// Authorities the signature must cover as @authority (host[:port]);
	// empty disables the check.
	Authorities []string
	// MaxAge bounds the signature's created timestamp; zero uses the strict
	// default (5 minutes).
	MaxAge time.Duration
	// MaxBodyBytes caps buffered request bodies; zero uses 16 MiB.
	MaxBodyBytes int64
	// Verifier shares a replay guard across requests; nil creates one.
	Verifier *rfc9421.HTTPVerifier
	// Signer, when set, signs responses with KeyID and Algorithm.
	Signer    crypto.Signer
	KeyID     string
	Algorithm string
	Logger    *slog.Logger
}

const defaultMaxBody = 16 << 20

// Middleware returns a handler that verifies each request and then calls
// next. Failures are answered with 401 and a generic body; the reason is
// logged only.
func Middleware(next http.Handler, o Options) http.Handler {
	if o.Resolver == nil {
		panic("verify: Options.Resolver is required")
	}
	v := o.Verifier
	if v == nil {
		v = rfc9421.NewHTTPVerifier()
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	maxBody := o.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	if o.Signer != nil {
		next = (&rfc9421.ResponseSigner{Verifier: v, PrivateKey: o.Signer, KeyID: o.KeyID, Algorithm: o.Algorithm}).Wrap(next)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentDID, err := verifyRequest(r, v, o, maxBody)
		if err != nil {
			log.Warn("sage: request rejected", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "did", agentDID, "reason", err)
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}
		r.Header.Set(HeaderVerifiedDID, agentDID)
		next.ServeHTTP(w, r)
	})
}

func verifyRequest(r *http.Request, v *rfc9421.HTTPVerifier, o Options, maxBody int64) (string, error) {
	inputs, err := rfc9421.ParseSignatureInput(r.Header.Get("Signature-Input"))
	if err != nil {
		return "", fmt.Errorf("signature-input: %w", err)
	}
	if len(inputs) == 0 {
		return "", errors.New("no signature")
	}
	var keyID string
	for _, p := range inputs {
		keyID = p.KeyID
		break
	}
	agentDID := rfc9421.KeyIDDID(keyID)
	if agentDID == "" {
		return "", errors.New("keyid carries no DID")
	}
	if h := r.Header.Get("X-SAGE-DID"); h != "" && h != agentDID {
		return agentDID, errors.New("X-SAGE-DID does not match keyid")
	}
	pub, err := o.Resolver.ResolvePublicKey(r.Context(), agentDID)
	if err != nil {
		return agentDID, fmt.Errorf("resolve key: %w", err)
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			return agentDID, fmt.Errorf("read body: %w", err)
		}
		if int64(len(body)) > maxBody {
			return agentDID, errors.New("body too large")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		defer func() { r.Body = io.NopCloser(bytes.NewReader(body)) }()
	}
	opts := rfc9421.StrictHTTPVerificationOptions()
	opts.ExpectedDID = agentDID
	opts.ExpectedAuthorities = o.Authorities
	if o.MaxAge > 0 {
		opts.MaxAge = o.MaxAge
	}
	if err := v.VerifyRequest(r, pub, opts); err != nil {
		return agentDID, err
	}
	return agentDID, nil
}

// ReverseProxy returns a verifying reverse proxy in front of upstream.
// Signed responses (when Options.Signer is set) cover the upstream's
// status, content-type and body and are bound to the request.
func ReverseProxy(upstream *url.URL, o Options) http.Handler {
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(upstream)
		pr.Out.Host = upstream.Host
		// The upstream must not see the caller's signature headers as its own.
		pr.Out.Header.Del("Signature")
		pr.Out.Header.Del("Signature-Input")
	}}
	return Middleware(proxy, o)
}
