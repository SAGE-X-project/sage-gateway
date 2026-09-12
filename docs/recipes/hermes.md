# Hermes agent

Hermes calls HTTP tools directly. Give it the gateway as the tool base URL
instead of the remote host:

```bash
sage-gateway client -listen 127.0.0.1:8081 -upstream https://tools.example.com \
  -key ~/.sage/agent-a.jwk -did did:sage:ethereum:0x1111…
export TOOLS_BASE_URL=http://127.0.0.1:8081
```

Requests to `$TOOLS_BASE_URL/<path>` are forwarded to
`https://tools.example.com/<path>` with a SAGE signature. Protect the tool
service with `sage-gateway serve` on the other side.
