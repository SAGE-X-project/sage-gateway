# Client recipes

Each recipe shows how to put a client that speaks plain HTTP behind
`sage-gateway client`, and an MCP server behind `sage-gateway serve`.
They assume two keys made with `sage-crypto generate` and the DIDs of both
agents. The recipes are configuration only; nothing in the clients changes.

| Recipe | Client |
|---|---|
| [claude-code.md](claude-code.md) | Claude Code (MCP over HTTP) |
| [codex.md](codex.md) | Codex CLI (MCP over HTTP) |
| [hermes.md](hermes.md) | Hermes agent (HTTP tools) |
