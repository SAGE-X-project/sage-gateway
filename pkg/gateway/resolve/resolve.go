// Package resolve maps an agent DID to the public key that verifies its
// RFC 9421 signatures: either from a static table configured by the
// operator, or from the on-chain registry through the sage DID manager
// with a TTL cache in front of it.
package resolve

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/sage-x-project/sage/pkg/agent/crypto/chain"
	"github.com/sage-x-project/sage/pkg/agent/did"
	dideth "github.com/sage-x-project/sage/pkg/agent/did/ethereum"
)

// ErrUnknownDID is returned when no key is known for the DID.
var ErrUnknownDID = errors.New("unknown agent DID")

// KeyResolver returns the signing public key of an agent.
type KeyResolver interface {
	ResolvePublicKey(ctx context.Context, agentDID string) (crypto.PublicKey, error)
}

// Static is a fixed DID -> key table.
type Static struct {
	mu   sync.RWMutex
	keys map[string]crypto.PublicKey
}

// NewStatic returns an empty table.
func NewStatic() *Static { return &Static{keys: map[string]crypto.PublicKey{}} }

// ParseStatic parses "did=hexkey;did=hexkey" as accepted by
// SAGE_TRUSTED_AGENTS. A 32-byte key is Ed25519; a 33- or 65-byte key is
// a compressed or uncompressed secp256k1 point.
func ParseStatic(spec string) (*Static, error) {
	s := NewStatic()
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		agentDID, keyHex, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("trusted agent entry %q: expected did=hexkey", entry)
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(keyHex), "0x"))
		if err != nil {
			return nil, fmt.Errorf("trusted agent %s: %w", agentDID, err)
		}
		pub, err := publicKeyFromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("trusted agent %s: %w", agentDID, err)
		}
		s.Add(strings.TrimSpace(agentDID), pub)
	}
	return s, nil
}

func publicKeyFromBytes(raw []byte) (crypto.PublicKey, error) {
	switch len(raw) {
	case ed25519.PublicKeySize:
		return ed25519.PublicKey(raw), nil
	case 33:
		return ethcrypto.DecompressPubkey(raw)
	case 65:
		return ethcrypto.UnmarshalPubkey(raw)
	}
	return nil, fmt.Errorf("unsupported public key length %d (32 Ed25519, 33 or 65 secp256k1)", len(raw))
}

// Add registers a key for a DID.
func (s *Static) Add(agentDID string, pub crypto.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[agentDID] = pub
}

// Len returns the number of entries.
func (s *Static) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// ResolvePublicKey implements KeyResolver.
func (s *Static) ResolvePublicKey(_ context.Context, agentDID string) (crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pub, ok := s.keys[agentDID]
	if !ok {
		return nil, ErrUnknownDID
	}
	return pub, nil
}

// Cached wraps a resolver with a TTL cache. Successful lookups are kept
// for TTL; failures for NegativeTTL so a flood of unknown DIDs does not
// turn into a flood of RPC calls (sage BACKLOG B-15).
type Cached struct {
	Next        KeyResolver
	TTL         time.Duration
	NegativeTTL time.Duration
	now         func() time.Time
	mu          sync.Mutex
	entries     map[string]cacheEntry
}

type cacheEntry struct {
	pub     crypto.PublicKey
	err     error
	expires time.Time
}

// NewCached returns a cache in front of next.
func NewCached(next KeyResolver, ttl, negativeTTL time.Duration) *Cached {
	return &Cached{Next: next, TTL: ttl, NegativeTTL: negativeTTL, now: time.Now, entries: map[string]cacheEntry{}}
}

// ResolvePublicKey implements KeyResolver.
func (c *Cached) ResolvePublicKey(ctx context.Context, agentDID string) (crypto.PublicKey, error) {
	c.mu.Lock()
	if e, ok := c.entries[agentDID]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.pub, e.err
	}
	c.mu.Unlock()

	pub, err := c.Next.ResolvePublicKey(ctx, agentDID)
	ttl := c.TTL
	if err != nil {
		ttl = c.NegativeTTL
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err // do not cache the caller's cancellation
		}
	}
	if ttl > 0 {
		c.mu.Lock()
		c.entries[agentDID] = cacheEntry{pub: pub, err: err, expires: c.now().Add(ttl)}
		c.mu.Unlock()
	}
	return pub, err
}

// Forget drops one DID from the cache (for example after a key rotation).
func (c *Cached) Forget(agentDID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, agentDID)
}

// DIDOptions configure on-chain resolution.
type DIDOptions struct {
	// Network is a sage chain preset name (sepolia, kairos, ...). RPCURL and
	// Registry override the preset when set.
	Network  string
	RPCURL   string
	Registry string
}

// NewDID returns a resolver backed by the sage DID manager for Ethereum
// networks. It registers the Ethereum DID client (the composition step the
// sage binaries do in internal/app).
func NewDID(opts DIDOptions) (KeyResolver, error) {
	preset, ok := chain.PresetFor(opts.Network)
	if !ok && (opts.RPCURL == "" || opts.Registry == "") {
		return nil, fmt.Errorf("unknown network %q and no rpc/registry override", opts.Network)
	}
	rpc, registry := preset.RPCURL, preset.RegistryAddress()
	if opts.RPCURL != "" {
		rpc = opts.RPCURL
	}
	if opts.Registry != "" {
		registry = opts.Registry
	}
	if rpc == "" || registry == "" {
		return nil, fmt.Errorf("network %q has no RPC URL or registry address; pass overrides", opts.Network)
	}
	dideth.Register()
	m := did.NewManager()
	if err := m.Configure(did.ChainEthereum, &did.RegistryConfig{
		Chain:           did.ChainEthereum,
		Network:         did.Network(preset.Network),
		ContractAddress: registry,
		RPCEndpoint:     rpc,
	}); err != nil {
		return nil, fmt.Errorf("configure DID manager: %w", err)
	}
	return &managerResolver{m: m}, nil
}

type managerResolver struct{ m *did.Manager }

func (r *managerResolver) ResolvePublicKey(ctx context.Context, agentDID string) (crypto.PublicKey, error) {
	pub, err := r.m.ResolvePublicKey(ctx, did.AgentDID(agentDID))
	if err != nil {
		return nil, err
	}
	switch k := pub.(type) {
	case crypto.PublicKey:
		return k, nil
	}
	return nil, fmt.Errorf("resolved key of %s has unexpected type %T", agentDID, pub)
}
