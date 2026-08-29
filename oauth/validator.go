package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ExtractTokenFromRequest extracts an OAuth bearer token from an HTTP request,
// per MCP authorization spec §Token Requirements:
//
//	"MCP client MUST use the Authorization request header field defined in
//	 OAuth 2.1 §5.1.1: Authorization: Bearer <access-token>"
//	"Access tokens MUST NOT be included in the URI query string"
//
// Only the Authorization header is accepted.
func ExtractTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// RequiresLocalValidation reports whether the auth layer should call
// ValidateToken on inbound bearers.
func (v *Verifier) RequiresLocalValidation() bool {
	return v.cfg.Enabled
}

// ValidateToken validates an OAuth bearer and returns claims.
//
// JWT bearers route through the JWKS-based external-JWT validator:
// signature + iss + aud + exp against the configured JWKS.
//
// Two cases soft-pass (return nil claims, nil error) — the auth layer accepts
// the request and forwards to ClickHouse, which is then the sole validator:
//
//  1. Opaque (non-JWT) bearers — RFC 7662 introspection is not implemented;
//     local validation isn't possible.
//  2. JWT bearers with neither Issuer nor JWKSURL configured — operator
//     hasn't told us where to fetch verification keys.
//
// Soft-pass preserves compatibility with deployments that rely entirely on
// downstream validation. Set StrictJWTOnly to reject opaque bearers locally.
func (v *Verifier) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	if !v.cfg.Enabled {
		return nil, nil
	}

	if token == "" {
		return nil, ErrMissingToken
	}

	if !looksLikeJWT(token) {
		if v.cfg.StrictJWTOnly {
			log.Error().Msg("OAuth token is not a JWT; StrictJWTOnly rejects opaque bearers")
			return nil, ErrInvalidToken
		}
		log.Debug().Msg("Bearer is opaque (not a JWT); skipping local validation")
		return nil, nil
	}
	if strings.TrimSpace(v.cfg.JWKSURL) == "" && strings.TrimSpace(v.cfg.Issuer) == "" {
		log.Debug().Msg("JWT received but neither oauth_issuer nor jwks_url is configured; skipping local validation")
		return nil, nil
	}
	claims, err := v.parseAndVerifyExternalJWT(ctx, token, v.cfg.Audience)
	if err != nil {
		logLegacyValidationFailure(err)
		return nil, err
	}

	return v.validateClaims(claims)
}

// logLegacyValidationFailure logs a parseAndVerifyExternalJWT failure for
// legacy ValidateToken callers, WITHOUT changing what ValidateToken itself
// returns (that compatibility contract — see jwt.go's jwtParseFailedPrefix/
// jwtMissingHeaderText doc comment and strict_jwt.go's errKidNotFound doc
// comment — is untouched by this function). Some of parseAndVerifyExternalJWT's
// failures embed raw, unverified, pre-signature JWT header content in their
// Error() text (a malformed/unexpected `alg`, `kid`, `nonce`, or `x5c`
// header value — see jwtHeaderParseError in jwt.go and errKidNotFound in
// strict_jwt.go); logging those via log.Error().Err(err) as before would put
// that attacker-controlled data into the log. This function classifies err
// into one of four buckets and logs accordingly:
//
//   - header-parse failure (jwt.ParseSigned rejected the token, or its
//     header was empty) — detected by matching err's fixed literal prefix
//     (jwtParseFailedPrefix/jwtMissingHeaderText); the attacker-controlled
//     content, if any, only ever appears AFTER that fixed prefix, so the
//     prefix match itself never touches attacker data. Logged as a fixed
//     message, no Err().
//   - kid-not-found failure (errKidNotFound, jwt.go) — detected
//     structurally via errors.Is, not text matching (see errKidNotFound's
//     doc comment for why this one CAN be structural while the header-parse
//     case above cannot: parseAndVerifyExternalJWT never strips this
//     sentinel from what it returns). Logged as a fixed message, no Err().
//   - any other ErrTransient failure — JWKS/discovery network or endpoint
//     errors (oauth/discovery.go, oauth/jwks.go). These embed operator
//     configuration (issuer/JWKS URLs) and transport errors, never
//     attacker-supplied token content, so they're logged in full via
//     .Err(err) exactly as before.
//   - anything else (signature-verification failure, issuer/audience
//     rejection) — logged as a fixed message plus a fixed string naming
//     which known sentinel (if any) the error satisfies, never the error's
//     own Error() text, as defense in depth against a future change to one
//     of these paths introducing attacker-controlled text.
func logLegacyValidationFailure(err error) {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, jwtParseFailedPrefix) || msg == jwtMissingHeaderText:
		log.Error().Msg("Failed to validate OAuth token: jwt header rejected")
	case errors.Is(err, errKidNotFound):
		log.Error().Msg("Failed to validate OAuth token: no JWK for token key id")
	case errors.Is(err, ErrTransient):
		log.Error().Err(err).Msg("Failed to validate OAuth token")
	default:
		log.Error().Str("class", legacyValidationErrorClass(err)).
			Msg("Failed to validate OAuth token: token validation failed")
	}
}

// legacyValidationErrorClass names the known sentinel err satisfies, for the
// catch-all branch of logLegacyValidationFailure. A fixed string, never the
// error's own Error() text.
func legacyValidationErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrInvalidToken):
		return "ErrInvalidToken"
	case errors.Is(err, ErrTokenExpired):
		return "ErrTokenExpired"
	case errors.Is(err, ErrInsufficientScopes):
		return "ErrInsufficientScopes"
	case errors.Is(err, ErrMissingToken):
		return "ErrMissingToken"
	default:
		return "unclassified"
	}
}

// validateClaims applies post-signature-verification checks: audience (slash-
// normalised), exp/nbf/iat (with clockSkewSecs tolerance), required scopes,
// and identity policy (email_verified, allowed domains).
func (v *Verifier) validateClaims(claims *Claims) (*Claims, error) {
	// Issuer enforcement happens in parseAndVerifyExternalJWT, the only path
	// that reaches here. Re-validating here would duplicate the check.

	if v.cfg.Audience != "" {
		if len(claims.Audience) == 0 {
			log.Error().Str("expected", v.cfg.Audience).Msg("OAuth token missing audience claim")
			return nil, ErrInvalidToken
		}
		if !audienceMatchesResource(claims.Audience, v.cfg.Audience) {
			// "expected" is operator configuration (safe to log). The old
			// "got" field logged the token's own audience claim VALUES —
			// removed; a count is enough to diagnose a mismatch without
			// putting token-derived strings in the log.
			log.Error().Str("expected", v.cfg.Audience).Int("got_count", len(claims.Audience)).
				Msg("OAuth token audience mismatch")
			return nil, ErrInvalidToken
		}
	}

	// exp/nbf/iat are logged as raw numeric timestamps (never as strings)
	// deliberately: unlike the audience/scope claim VALUES removed below,
	// these are needed for clock-skew diagnosis and, because they're read
	// from a claims map claimsFromRawClaims already produced from a
	// signature-verified token by the time validateClaims runs, they carry
	// no unverified/attacker-controlled content — a signature-verified
	// integer timestamp isn't the kind of string data this change targets.
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+clockSkewSecs {
		log.Error().Int64("exp", claims.ExpiresAt).Msg("OAuth token expired")
		return nil, ErrTokenExpired
	}
	if claims.NotBefore > 0 && now+clockSkewSecs < claims.NotBefore {
		log.Error().Int64("nbf", claims.NotBefore).Msg("OAuth token not yet valid")
		return nil, ErrInvalidToken
	}
	if claims.IssuedAt > 0 && claims.IssuedAt > now+clockSkewSecs {
		log.Error().Int64("iat", claims.IssuedAt).Msg("OAuth token issued in the future")
		return nil, ErrInvalidToken
	}

	if len(v.cfg.RequiredScopes) > 0 {
		if !HasRequiredScopes(claims.Scopes, v.cfg.RequiredScopes) {
			// "required" is operator configuration (safe to log). The old
			// "got" field logged the token's own scope claim VALUES —
			// removed in favor of a count, same rationale as the audience
			// mismatch above.
			log.Error().Strs("required", v.cfg.RequiredScopes).Int("got_count", len(claims.Scopes)).
				Msg("OAuth token missing required scopes")
			return nil, ErrInsufficientScopes
		}
	}

	return claims, nil
}

// ValidateUpstreamIdentityToken parses an upstream identity token using the
// JWKS path (no soft-pass). Used by the broker's /oauth/callback after
// exchanging the upstream authorization code for an id_token: it verifies the
// redemption was legitimate (signature/iss/aud/exp) without imposing
// identity policy — domain allow-listing and verified-email enforcement now
// live in the CH-side ch-jwt-verify sidecar.
func (v *Verifier) ValidateUpstreamIdentityToken(ctx context.Context, token, expectedAudience string) (*Claims, error) {
	return v.parseAndVerifyExternalJWT(ctx, token, expectedAudience)
}
