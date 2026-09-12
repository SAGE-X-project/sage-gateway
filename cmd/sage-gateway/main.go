// sage-gateway puts SAGE (RFC 9421) signatures in front of and behind HTTP
// services such as MCP servers.
//
//	sage-gateway serve  -listen :8443 -upstream http://127.0.0.1:3000 -key agent.jwk -did did:sage:... \
//	    [-trusted "did=hexkey;..."] [-network sepolia] [-authority host:port] [-sign-responses]
//	sage-gateway client -listen 127.0.0.1:8080 -upstream https://agent-b.example -key agent.jwk -did did:sage:... \
//	    [-peer-did did:sage:...] [-trusted "did=hexkey"] [-network sepolia]
//	sage-gateway version
//
// serve verifies inbound requests (static trusted table and/or on-chain DID
// resolution) before forwarding them to the upstream, and signs the
// responses when -sign-responses is set. client accepts unsigned requests
// from a local client, signs them and forwards them to the upstream,
// verifying signed responses when a peer key source is configured.
package main

import (
	"context"
	"crypto"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sage-x-project/sage-gateway/pkg/gateway/keyfile"
	"github.com/sage-x-project/sage-gateway/pkg/gateway/resolve"
	"github.com/sage-x-project/sage-gateway/pkg/gateway/sign"
	"github.com/sage-x-project/sage-gateway/pkg/gateway/verify"
)

// Version is set at build time.
var Version = "dev"

type common struct {
	listen, upstream, keyFile, keyFormat, storageDir, keyID, did, keyIDParam string
	trusted, network, rpc, registry                                          string
	cacheTTL, negTTL                                                         time.Duration
}

func (c *common) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.listen, "listen", "127.0.0.1:8080", "address to listen on")
	fs.StringVar(&c.upstream, "upstream", "", "upstream base URL (required)")
	fs.StringVar(&c.keyFile, "key", "", "signing key file (JWK or PEM from sage-crypto)")
	fs.StringVar(&c.keyFormat, "key-format", "jwk", "key file format: jwk or pem")
	fs.StringVar(&c.storageDir, "storage-dir", "", "sage key storage directory (alternative to -key)")
	fs.StringVar(&c.keyID, "key-id", "", "key id inside -storage-dir")
	fs.StringVar(&c.did, "did", "", "this agent's DID (required when signing)")
	fs.StringVar(&c.keyIDParam, "keyid", "", "RFC 9421 keyid parameter; defaults to -did")
	fs.StringVar(&c.trusted, "trusted", os.Getenv("SAGE_TRUSTED_AGENTS"), "static trusted agents: did=hexkey;did=hexkey (default $SAGE_TRUSTED_AGENTS)")
	fs.StringVar(&c.network, "network", "", "chain preset for on-chain DID resolution (sepolia, kairos, ...)")
	fs.StringVar(&c.rpc, "rpc", "", "RPC URL override for -network")
	fs.StringVar(&c.registry, "registry", "", "registry address override for -network")
	fs.DurationVar(&c.cacheTTL, "cache-ttl", 5*time.Minute, "TTL for resolved keys")
	fs.DurationVar(&c.negTTL, "negative-cache-ttl", 30*time.Second, "TTL for failed resolutions")
}

// resolver builds the key resolver from -trusted and/or -network. Static
// entries win; DIDs not in the table fall through to the chain.
func (c *common) resolver() (resolve.KeyResolver, error) {
	var static *resolve.Static
	if c.trusted != "" {
		s, err := resolve.ParseStatic(c.trusted)
		if err != nil {
			return nil, err
		}
		static = s
	}
	if c.network == "" && c.rpc == "" {
		if static == nil {
			return nil, nil
		}
		return static, nil
	}
	chainResolver, err := resolve.NewDID(resolve.DIDOptions{Network: c.network, RPCURL: c.rpc, Registry: c.registry})
	if err != nil {
		return nil, err
	}
	cached := resolve.NewCached(chainResolver, c.cacheTTL, c.negTTL)
	if static == nil {
		return cached, nil
	}
	return chain{static: static, next: cached}, nil
}

type chain struct {
	static *resolve.Static
	next   resolve.KeyResolver
}

func (c chain) ResolvePublicKey(ctx context.Context, agentDID string) (crypto.PublicKey, error) {
	if pub, err := c.static.ResolvePublicKey(ctx, agentDID); err == nil {
		return pub, nil
	}
	return c.next.ResolvePublicKey(ctx, agentDID)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	case "version":
		fmt.Println("sage-gateway", Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sage-gateway:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sage-gateway <serve|client|version> [flags]")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var c common
	c.flags(fs)
	authorities := fs.String("authority", "", "comma-separated authorities requests must be addressed to (host[:port])")
	signResponses := fs.Bool("sign-responses", false, "sign responses with -key")
	maxAge := fs.Duration("max-age", 5*time.Minute, "maximum signature age")
	_ = fs.Parse(args)

	upstream, err := parseUpstream(c.upstream)
	if err != nil {
		return err
	}
	res, err := c.resolver()
	if err != nil {
		return err
	}
	if res == nil {
		return errors.New("serve needs a key source: -trusted (or $SAGE_TRUSTED_AGENTS) and/or -network")
	}
	opts := verify.Options{Resolver: res, MaxAge: *maxAge, Logger: slog.Default()}
	if *authorities != "" {
		opts.Authorities = strings.Split(*authorities, ",")
	}
	if *signResponses {
		kp, err := keyfile.Load(keyfile.Source{File: c.keyFile, Format: c.keyFormat, StorageDir: c.storageDir, KeyID: c.keyID})
		if err != nil {
			return err
		}
		signer, alg, err := keyfile.Signer(kp)
		if err != nil {
			return err
		}
		if c.did == "" {
			return errors.New("-did is required with -sign-responses")
		}
		opts.Signer, opts.Algorithm, opts.KeyID = signer, alg, c.keyIDParam
		if opts.KeyID == "" {
			opts.KeyID = c.did
		}
	}
	slog.Info("sage-gateway serve", "listen", c.listen, "upstream", upstream.String(), "sign_responses", *signResponses)
	return serve(c.listen, verify.ReverseProxy(upstream, opts))
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var c common
	c.flags(fs)
	peerDID := fs.String("peer-did", "", "expected signer of responses; enables response verification with -trusted/-network")
	_ = fs.Parse(args)

	upstream, err := parseUpstream(c.upstream)
	if err != nil {
		return err
	}
	kp, err := keyfile.Load(keyfile.Source{File: c.keyFile, Format: c.keyFormat, StorageDir: c.storageDir, KeyID: c.keyID})
	if err != nil {
		return err
	}
	signer, alg, err := keyfile.Signer(kp)
	if err != nil {
		return err
	}
	if c.did == "" {
		return errors.New("-did is required")
	}
	t := &sign.Transport{Signer: signer, DID: c.did, KeyID: c.keyIDParam, Algorithm: alg}
	if *peerDID != "" {
		res, err := c.resolver()
		if err != nil {
			return err
		}
		if res == nil {
			return errors.New("-peer-did needs -trusted and/or -network to resolve the peer key")
		}
		t.PeerResolver, t.PeerDID = res, *peerDID
	}
	slog.Info("sage-gateway client", "listen", c.listen, "upstream", upstream.String(), "did", c.did, "key", keyfile.KeyID(kp), "verify_responses", *peerDID != "")
	return serve(c.listen, sign.ForwardProxy(upstream, t))
}

func parseUpstream(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("-upstream is required")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid -upstream %q", s)
	}
	return u, nil
}

func serve(addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
