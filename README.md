# sage-gateway

Puts SAGE signatures (HTTP Message Signatures, RFC 9421, profiled by
[sage-spec](https://github.com/SAGE-X-project/sage-spec)) in front of and
behind HTTP services such as MCP servers, so agents that cannot sign or
verify themselves still get authenticated, tamper-evident, replay-protected
calls. It imports the Go core [`sage`](https://github.com/SAGE-X-project/sage)
as a library and adds nothing to the protocol.

| Mode | Command | What it does |
|---|---|---|
| Inbound (protect a server) | `sage-gateway serve` | Verifies every request's signature against a trusted-key table and/or the on-chain registry, forwards it to the upstream with `X-SAGE-Verified-DID`, and optionally signs the response bound to the request |
| Outbound (sign for a client) | `sage-gateway client` | Accepts unsigned requests from a local client, signs them with the agent's key, forwards them, and optionally verifies the signed responses |

```
MCP client ──(plain HTTP, localhost)──▶ sage-gateway client ──(signed)──▶ sage-gateway serve ──(plain, verified DID)──▶ MCP server
```

## Install

```bash
go install github.com/sage-x-project/sage-gateway/cmd/sage-gateway@latest
# a key from the Go core's CLI
sage-crypto generate -t ed25519 -o agent-a.jwk --format jwk
```

## Protect an MCP server

```bash
export SAGE_TRUSTED_AGENTS="did:sage:ethereum:0x1111…=<hex ed25519 public key>"
sage-gateway serve \
  -listen 0.0.0.0:8443 \
  -upstream http://127.0.0.1:3000 \
  -authority mcp.example.com:8443 \
  -sign-responses -key agent-b.jwk -did did:sage:ethereum:0x2222…
```

With `-network sepolia` (and optional `-rpc`, `-registry`) unknown DIDs are
resolved from the AgentCard registry; results are cached (`-cache-ttl`,
`-negative-cache-ttl`). Static entries win over the chain.

What `serve` checks on every request:

1. `Signature-Input` and `Signature` are present; `keyid` is `<DID>` or
   `<DID>#fragment`; `X-SAGE-DID`, when present, equals that DID.
2. The DID's key is known (static table or registry; inactive agents fail).
3. Strict RFC 9421 verification: `@method`, `@target-uri`, `@authority`
   covered; `content-digest` covered and correct when there is a body;
   `nonce` present and not seen before under that key; `created` within
   `-max-age` (default 5 min) and not in the future.
4. `@authority` matches one of `-authority` when set.

Rejections return `401 authentication failed`; the reason is logged only.
The upstream receives the request without the signature headers and with
`X-SAGE-Verified-DID` set, and may authorise on that.

What it does not do (yet): capability or scope checks, rate limiting before
verification, session (HPKE) establishment, stdio MCP bridging. See
"Roadmap".

## Sign for a client

```bash
sage-gateway client \
  -listen 127.0.0.1:8080 \
  -upstream https://mcp.example.com:8443 \
  -key agent-a.jwk -did did:sage:ethereum:0x1111… \
  -peer-did did:sage:ethereum:0x2222… -trusted "did:sage:ethereum:0x2222…=<hex key>"
```

Point the MCP client at `http://127.0.0.1:8080/`. Every request is signed
over `@method @target-uri @authority content-type content-digest x-sage-did
date` with a fresh nonce; when `-peer-did` is set, responses must be signed
by that agent and bound to the request (`@status`, `content-digest`, and the
request's method, target, authority, digest and signature via `;req`).

Recipes for specific clients: [`docs/recipes/`](docs/recipes/).

## Library use

```go
import (
    "github.com/sage-x-project/sage-gateway/pkg/gateway/resolve"
    "github.com/sage-x-project/sage-gateway/pkg/gateway/sign"
    "github.com/sage-x-project/sage-gateway/pkg/gateway/verify"
)

trusted, _ := resolve.ParseStatic(os.Getenv("SAGE_TRUSTED_AGENTS"))
handler := verify.Middleware(mcpHandler, verify.Options{Resolver: trusted, Signer: priv, KeyID: myDID, Algorithm: "ed25519"})

client := &http.Client{Transport: &sign.Transport{Signer: priv, DID: myDID, Algorithm: "ed25519", PeerResolver: trusted, PeerDID: peerDID}}
```

`resolve.NewCached` wraps any resolver with a TTL cache; `resolve.NewDID`
builds the registry-backed resolver from a chain preset.

## Conformance

The signing and verification paths are the Go core's; this repository adds
header handling, key resolution and proxying. The Go core is checked
against the sage-spec vectors in its CI; the tests here cover the round trip
(sign, verify, respond, verify response), unknown signers, replay, authority
binding and body limits.

## Roadmap

- stdio MCP bridge (`sage-gateway mcp -- <server command>`) exposing a
  signed HTTP endpoint.
- Capability and scope authorisation from the agent card.
- HPKE session mode for payload encryption between two gateways.

## Licence

LGPL-3.0 (see `LICENSE`), the licence of the Go core it links.
