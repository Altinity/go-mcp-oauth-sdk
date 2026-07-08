package oauth

import "time"

// OAuthConfig defines configuration for OAuth 2.0 authentication.
//
// Every flag-tagged field is settable via CLI flag (`flag:` tag) or env var
// (`env:` tag). The env-var convention here is `MCP_OAUTH_<UPPER_SNAKE>` so
// secrets like SigningSecret can be injected from a Kubernetes Secret via
// the Helm chart's env: array using valueFrom.secretKeyRef.
type OAuthConfig struct {
	// Enabled enables OAuth authentication
	Enabled bool `json:"enabled" yaml:"enabled" flag:"oauth-enabled" env:"MCP_OAUTH_ENABLED" desc:"Enable OAuth 2.0 authentication"`

	// Issuer is the OAuth token issuer URL for token validation (e.g., "https://accounts.google.com")
	Issuer string `json:"issuer" yaml:"issuer" flag:"oauth-issuer" env:"MCP_OAUTH_ISSUER" desc:"OAuth token issuer URL for validation"`

	// JWKSURL is the URL to fetch JSON Web Key Set for token validation
	// If empty, will be discovered from issuer's .well-known/openid-configuration
	JWKSURL string `json:"jwks_url" yaml:"jwks_url" flag:"oauth-jwks-url" env:"MCP_OAUTH_JWKS_URL" desc:"URL to fetch JWKS for token validation"`

	// Audience is the expected audience claim in the token
	Audience string `json:"audience" yaml:"audience" flag:"oauth-audience" env:"MCP_OAUTH_AUDIENCE" desc:"Expected audience claim in OAuth token"`

	// PublicResourceURL is the externally visible protected resource base URL.
	// When empty, it is inferred from the request host/prefix or Audience path.
	PublicResourceURL string `json:"public_resource_url" yaml:"public_resource_url" flag:"oauth-public-resource-url" env:"MCP_OAUTH_PUBLIC_RESOURCE_URL" desc:"Externally visible protected resource base URL"`

	// PublicAuthServerURL is the externally visible authorization server base URL.
	// When empty, it is inferred from the request host/prefix or Issuer path.
	PublicAuthServerURL string `json:"public_auth_server_url" yaml:"public_auth_server_url" flag:"oauth-public-auth-server-url" env:"MCP_OAUTH_PUBLIC_AUTH_SERVER_URL" desc:"Externally visible OAuth authorization server base URL"`

	// ClientID is the OAuth client ID (used for client credentials flow or validation)
	ClientID string `json:"client_id" yaml:"client_id" flag:"oauth-client-id" env:"MCP_OAUTH_CLIENT_ID" desc:"OAuth client ID"`

	// ClientSecret is the OAuth client secret (used for client credentials flow)
	ClientSecret string `json:"client_secret" yaml:"client_secret" flag:"oauth-client-secret" env:"MCP_OAUTH_CLIENT_SECRET" desc:"OAuth client secret"`

	// TokenURL is the OAuth token endpoint URL (used for client credentials flow)
	TokenURL string `json:"token_url" yaml:"token_url" flag:"oauth-token-url" env:"MCP_OAUTH_TOKEN_URL" desc:"OAuth token endpoint URL"`

	// AuthURL is the OAuth authorization endpoint URL (used for authorization code flow)
	AuthURL string `json:"auth_url" yaml:"auth_url" flag:"oauth-auth-url" env:"MCP_OAUTH_AUTH_URL" desc:"OAuth authorization endpoint URL"`

	// UserInfoURL is the upstream OpenID Connect userinfo endpoint URL.
	// If empty, it will be discovered from issuer metadata when needed.
	UserInfoURL string `json:"userinfo_url" yaml:"userinfo_url" flag:"oauth-userinfo-url" env:"MCP_OAUTH_USERINFO_URL" desc:"OAuth/OpenID Connect userinfo endpoint URL"`

	// Scopes is the list of OAuth scopes to request
	Scopes []string `json:"scopes" yaml:"scopes" flag:"oauth-scopes" env:"MCP_OAUTH_SCOPES" desc:"OAuth scopes to request"`

	// UpstreamOfflineAccess opts broker mode into appending
	// `offline_access` to the scope sent upstream. Used mainly so the IdP's
	// consent screen offers long-lived sessions; the upstream refresh token
	// MCP receives is currently discarded. v1 issues NO downstream refresh
	// tokens to CIMD clients — they re-authorize via /oauth/authorize when
	// the access token expires. See #115 § Refresh-token policy.
	// Default false. Effect is upstream-only; this flag does not turn on
	// any downstream refresh-token issuance.
	UpstreamOfflineAccess bool `json:"upstream_offline_access" yaml:"upstream_offline_access" flag:"oauth-upstream-offline-access" env:"MCP_OAUTH_UPSTREAM_OFFLINE_ACCESS" desc:"Append offline_access to the upstream scope so the IdP's consent screen offers long-lived sessions. v1 does NOT issue downstream refresh tokens regardless of this flag — clients re-authorize via /oauth/authorize."`

	// UpstreamForceConsent forces `prompt=consent` on every upstream
	// /authorize call (Google-family providers only). The first authorize
	// for a user with `upstream_offline_access: true` always triggers the
	// consent screen anyway — Google mints the refresh_token there and
	// remembers it. Subsequent silent-SSO redemptions reuse the existing
	// grant without re-prompting. Set this to true only when the operator
	// needs to force re-enrollment (e.g. after rotating the upstream OAuth
	// client). Default false avoids the surprise re-consent on every login.
	UpstreamForceConsent bool `json:"upstream_force_consent" yaml:"upstream_force_consent" flag:"oauth-upstream-force-consent" env:"MCP_OAUTH_UPSTREAM_FORCE_CONSENT" desc:"Force prompt=consent on every upstream /authorize (Google providers only). Default false reuses Google's stored offline-access grant after the first consent."`

	// Broker enables altinity-mcp to act as the OAuth AS to MCP clients
	// (CIMD, /authorize + /callback + /token) while brokering an upstream IdP
	// that does not support CIMD natively (e.g. Google). When false, MCP is
	// only a protected resource and the external authorization server handles
	// client authorization. CH auth wire format (Bearer vs Basic) is a host
	// service detail, not an SDK config mode.
	// Requires: issuer, client_id, client_secret, auth_url, token_url, signing_secret.
	Broker bool `json:"broker" yaml:"broker" flag:"oauth-broker" env:"MCP_OAUTH_BROKER" desc:"Enable OAuth broker: MCP acts as AS to MCP clients, brokers upstream IdP. CH auth (Bearer/Basic) auto-detected per endpoint."`

	// RequiredScopes is the list of scopes required for access (token must have all of these)
	RequiredScopes []string `json:"required_scopes" yaml:"required_scopes" flag:"oauth-required-scopes" env:"MCP_OAUTH_REQUIRED_SCOPES" desc:"Required OAuth scopes for access"`

	// AuthorizationPath configures the relative path for the authorization endpoint.
	AuthorizationPath string `json:"authorization_path" yaml:"authorization_path" flag:"oauth-authorization-path" env:"MCP_OAUTH_AUTHORIZATION_PATH" desc:"Relative path for OAuth authorization endpoint"`

	// CallbackPath configures the relative path for the upstream IdP callback handler.
	CallbackPath string `json:"callback_path" yaml:"callback_path" flag:"oauth-callback-path" env:"MCP_OAUTH_CALLBACK_PATH" desc:"Relative path for OAuth upstream callback endpoint"`

	// TokenPath configures the relative path for the token endpoint.
	TokenPath string `json:"token_path" yaml:"token_path" flag:"oauth-token-path" env:"MCP_OAUTH_TOKEN_PATH" desc:"Relative path for OAuth token endpoint"`

	// AccessTokenTTLSeconds controls how long minted access tokens remain valid.
	AccessTokenTTLSeconds int `json:"access_token_ttl_seconds" yaml:"access_token_ttl_seconds" flag:"oauth-access-token-ttl-seconds" env:"MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS" desc:"Access token lifetime in seconds"`

	// RefreshTokenTTLSeconds controls how long minted refresh tokens remain valid.
	RefreshTokenTTLSeconds int `json:"refresh_token_ttl_seconds" yaml:"refresh_token_ttl_seconds" flag:"oauth-refresh-token-ttl-seconds" env:"MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS" desc:"Refresh token lifetime in seconds"`

	// JWKSCacheTTL bounds how long a JWKS document (and its sibling
	// auth-server metadata response) stays cached before the Verifier
	// re-fetches. Zero falls back to the package default (5 minutes).
	// Operators tune this against the IdP's key-rotation cadence: shorter
	// TTLs narrow the per-replica drift window during rotation at the
	// cost of more JWKS HTTP round trips.
	JWKSCacheTTL time.Duration `json:"jwks_cache_ttl" yaml:"jwks_cache_ttl" flag:"oauth-jwks-cache-ttl" env:"MCP_OAUTH_JWKS_CACHE_TTL" desc:"JWKS / auth-server metadata cache TTL (default 5m)"`

	// SigningSecret is the server-side symmetric secret used to HKDF-derive
	// keys for every stateless OAuth JWE this server mints: pending-auth
	// state (the upstream `state` parameter) and the downstream auth-code
	// returned from /oauth/callback. Required when Broker=true. Per #115
	// v1 issues no downstream refresh tokens and no DCR client_secrets.
	SigningSecret string `json:"signing_secret" yaml:"signing_secret" flag:"oauth-signing-secret" env:"MCP_OAUTH_SIGNING_SECRET" desc:"Server-side HKDF master secret for OAuth JWE artifacts (pending-auth state, downstream auth codes). Required when broker: true."`

	// StrictJWTOnly rejects non-JWT bearer tokens with ErrInvalidToken
	// instead of soft-passing them. Default false.
	StrictJWTOnly bool `yaml:"strict_jwt_only" json:"strict_jwt_only"`

	// RoleClaim names the JWT claim that holds a JSON array of ClickHouse role
	// names (e.g. "https://clickhouse/roles"). When set, the host activates
	// only the RoleFilter-matching subset of those roles per ClickHouse request
	// (HTTP `role=` query params), narrowing the user's active roles. Empty
	// disables the feature. The claim is read from Claims.Extra, so a
	// namespaced custom claim works without any further wiring.
	RoleClaim string `json:"role_claim" yaml:"role_claim" flag:"oauth-role-claim" env:"MCP_OAUTH_ROLE_CLAIM" desc:"JWT claim holding a JSON array of ClickHouse role names to activate per request (empty disables)"`

	// RoleFilter is an optional regex narrowing which RoleClaim roles are
	// activated (e.g. "_mcp$"). When empty, every role in the claim is
	// activated; when set, it stops a misconfigured/over-broad claim from
	// activating real-data roles. Host enforcement decides empty-set behavior
	// (altinity-mcp fails closed). Anchor it — it is a partial match.
	RoleFilter string `json:"role_filter" yaml:"role_filter" flag:"oauth-role-filter" env:"MCP_OAUTH_ROLE_FILTER" desc:"Optional regex narrowing which role_claim roles are activated (empty = all claim roles)"`

	// UsernameClaim names the JWT claim whose string value is used as the
	// ClickHouse Basic-auth username on the sidecar fallback path. Empty keeps
	// the host's default behavior (email + namespaced */email fallback). When
	// set, the host does a strict top-level lookup of this claim and fails
	// closed if it is missing/empty/non-string — never silently falling back to
	// another identity. The claim is an unverified hint only: ClickHouse /
	// ch-jwt-verify still validate the JWT. Must match the sidecar's
	// identity.username_claim.
	UsernameClaim string `json:"username_claim" yaml:"username_claim" flag:"oauth-username-claim" env:"MCP_OAUTH_USERNAME_CLAIM" desc:"JWT claim used as the ClickHouse Basic-auth username on the sidecar path (empty = default email + namespaced fallback)"`
}
