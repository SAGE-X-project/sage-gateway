package resolve

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type counting struct {
	calls int
	pub   crypto.PublicKey
	err   error
}

func (c *counting) ResolvePublicKey(context.Context, string) (crypto.PublicKey, error) {
	c.calls++
	return c.pub, c.err
}

func TestParseStatic(t *testing.T) {
	pub := ed25519.PublicKey(make([]byte, 32))
	s, err := ParseStatic("did:sage:ethereum:0xa=" + hex.EncodeToString(pub) + "; did:sage:ethereum:0xb = 0x" + hex.EncodeToString(pub) + ";")
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Fatalf("len %d", s.Len())
	}
	if _, err := s.ResolvePublicKey(context.Background(), "did:sage:ethereum:0xc"); !errors.Is(err, ErrUnknownDID) {
		t.Fatalf("unknown: %v", err)
	}
	for _, bad := range []string{"nodid", "did:x=zz", "did:x=00"} {
		if _, err := ParseStatic(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCachedTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	next := &counting{pub: ed25519.PublicKey(make([]byte, 32))}
	c := NewCached(next, time.Minute, 10*time.Second)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.ResolvePublicKey(ctx, "did:a"); err != nil {
			t.Fatal(err)
		}
	}
	if next.calls != 1 {
		t.Fatalf("calls %d, want 1", next.calls)
	}
	now = now.Add(61 * time.Second)
	_, _ = c.ResolvePublicKey(ctx, "did:a")
	if next.calls != 2 {
		t.Fatalf("calls after expiry %d, want 2", next.calls)
	}

	// Failures are cached for the negative TTL only.
	failing := &counting{err: errors.New("rpc down")}
	c = NewCached(failing, time.Minute, 10*time.Second)
	c.now = func() time.Time { return now }
	_, _ = c.ResolvePublicKey(ctx, "did:b")
	_, _ = c.ResolvePublicKey(ctx, "did:b")
	if failing.calls != 1 {
		t.Fatalf("negative cache: calls %d", failing.calls)
	}
	now = now.Add(11 * time.Second)
	_, _ = c.ResolvePublicKey(ctx, "did:b")
	if failing.calls != 2 {
		t.Fatalf("negative expiry: calls %d", failing.calls)
	}

	// Cancellation is never cached.
	cancelled := &counting{err: context.Canceled}
	c = NewCached(cancelled, time.Minute, 10*time.Second)
	_, _ = c.ResolvePublicKey(ctx, "did:c")
	_, _ = c.ResolvePublicKey(ctx, "did:c")
	if cancelled.calls != 2 {
		t.Fatalf("cancellation cached: calls %d", cancelled.calls)
	}
}
