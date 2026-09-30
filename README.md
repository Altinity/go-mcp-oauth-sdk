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

## Email identities

Services authenticating by email can call `oauth.ResolveEmailIdentity` after
JWT validation. A standard `email` uses its standard `email_verified` evidence.
When the standard email is blank, the resolver accepts exactly one nonblank
string claim ending in `/email`, with verification supplied only by the
boolean `true` at its matching `/email_verified` key. Standard verification
flags and flags from other namespaces do not verify a namespaced email.
Multiple usable namespaced emails are rejected, even when their values match.

Resolve once, bind the requested username to the returned email, then call
`oauth.ValidateIdentityClaims` with a shallow copy of the original claims whose
`Email` and `EmailVerified` fields contain the resolved values. This applies
verified-email and domain restrictions to the email used for authentication
without modifying the original claims. The resolver itself does not enforce
either policy. `EmailFromNamespacedExtra` remains a username-hint helper and
does not establish verification provenance.
