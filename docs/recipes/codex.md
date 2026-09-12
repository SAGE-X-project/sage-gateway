# Codex CLI

Codex configures MCP servers in `~/.codex/config.toml`. Use the same local
signing gateway as in the Claude Code recipe and point Codex at it:

```toml
[mcp_servers.tools]
url = "http://127.0.0.1:8080/mcp"
```

Start `sage-gateway client` before Codex; the gateway signs each request
with the agent key and verifies signed responses when `-peer-did` is set.
