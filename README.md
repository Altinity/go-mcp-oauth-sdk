# go-mcp-oauth-sdk

Shared Go OAuth 2.0 / OIDC JWT verifier and JWE helpers extracted from
[altinity-mcp](https://github.com/Altinity/altinity-mcp). Lets multiple
Altinity services consume a single, canonical implementation of token
verification, upstream IdP discovery, and broker-mode helpers.

## Packages

- **`oauth/`** — OAuth 2.0 / OIDC bearer-token verifier: JWKS fetching,
  RFC 8414 / OpenID Connect discovery, claim parsing, domain policy, and
  Bearer-header helpers. Configurable via `OAuthConfig`.
- **`jwe_auth/`** — JWE token generator and verifier used for issuing
  short-lived broker tokens scoped to a specific client / TLS identity.
- **`broker/`** — Stateless helpers for OAuth broker-mode: PKCE, auth-code
  HKDF derivation, upstream metadata fetch, etc. Pure functions only —
  route handlers stay with the host service.
