# apikeykit

Agentic-first API key management service. Generate, manage, rotate, and verify API keys with scopes, TTL, and audit logging. Plain text API, agent-driven, single Go binary with JSON file storage.

## Quick Start

```bash
# Build
make build

# Run (defaults to :7700)
./apikeykit

# Or with custom config
./apikeykit -addr :8080 -db /data/keys.json -secret my-secret
```

## Auth Flow

```bash
# 1. Request OTP (logged to stderr in dev mode)
curl -X POST http://localhost:7700/auth/request -d 'email=agent@example.com'

# 2. Verify OTP to get bearer token
curl -X POST http://localhost:7700/auth/verify -d 'email=agent@example.com&code=123456'
# Returns: token=abc123...

# 3. Use token for all subsequent requests
curl -H "Authorization: Bearer abc123..." http://localhost:7700/keys
```

## API Reference

### Keys

```bash
# Create a key (secret shown only once!)
curl -H "Authorization: Bearer <token>" \
  -X POST http://localhost:7700/keys \
  -d 'name=my-api-key&scopes=read,write&ttl=3600'
# handle=key_abc12 secret=ak_live_xxx... warning=save the secret now

# List keys
curl -H "Authorization: Bearer <token>" http://localhost:7700/keys

# Get key details
curl -H "Authorization: Bearer <token>" http://localhost:7700/keys/key_abc12

# Rotate key secret (old one invalidated)
curl -H "Authorization: Bearer <token>" \
  -X POST http://localhost:7700/keys/key_abc12/rotate

# Verify a key secret
curl -H "Authorization: Bearer <token>" \
  -X POST http://localhost:7700/keys/key_abc12/verify \
  -d 'secret=ak_live_xxx'

# Delete/revoke a key
curl -H "Authorization: Bearer <token>" \
  -X DELETE http://localhost:7700/keys/key_abc12
```

### Workspaces

```bash
curl -H "Authorization: Bearer <token>" http://localhost:7700/workspaces
```

### Audit Log

```bash
curl -H "Authorization: Bearer <token>" http://localhost:7700/audit?limit=20
```

### MCP (Model Context Protocol)

```bash
curl -X POST http://localhost:7700/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Self-Documenting

```bash
curl http://localhost:7700/help
# or
curl http://localhost:7700/.well-known/agent.md
```

## Response Format

- **Plain text** (default): `key=value` pairs, one record per line
- **JSON**: via `Accept: application/json` header or `?format=json` query param
- **Errors**: `error: <message> | hint: <what to do next>`

## Configuration

| Flag    | Env Var             | Default              | Description                          |
|---------|---------------------|----------------------|--------------------------------------|
| -addr   | APIKEYKIT_ADDR      | :7700                | Listen address                       |
| -db     | APIKEYKIT_DB        | ./apikeykit.json     | Database file path                   |
| -secret | APIKEYKIT_SECRET    | (auto-generated)     | Token signing secret                 |
| -smtp   | APIKEYKIT_SMTP      | (empty = stderr)     | SMTP server for OTP email            |

## Build

```bash
make build    # CGO_ENABLED=0, single binary
make test     # go test -race
make vet      # go vet
```

## License

MIT
