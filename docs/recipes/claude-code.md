# Claude Code

Claude Code reaches remote MCP servers over HTTP. Run the signing gateway
locally and register its address as the MCP server.

1. Start the client gateway with the agent's key:

   ```bash
   sage-gateway client -listen 127.0.0.1:8080 \
     -upstream https://mcp.example.com:8443 \
     -key ~/.sage/agent-a.jwk -did did:sage:ethereum:0x1111… \
     -peer-did did:sage:ethereum:0x2222… -network sepolia
   ```

2. Register the local endpoint:

   ```bash
   claude mcp add --transport http tools http://127.0.0.1:8080/mcp
   ```

3. On the server side, the operator runs `sage-gateway serve` in front of
   the MCP server with `SAGE_TRUSTED_AGENTS` or `-network` so that
   `did:sage:ethereum:0x1111…` is known, and `-sign-responses` so step 1's
   `-peer-did` verification succeeds.

Every tool call is then signed with the agent's key and every result is
verified against the server's key; an unsigned or replayed call is refused
with 401 before it reaches the MCP server.
