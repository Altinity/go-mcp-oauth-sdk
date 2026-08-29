package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rs/zerolog/log"
)

// looksLikeJWT is a cheap structural check: a JWS in compact form is three
// base64url segments joined by dots. False positives on garbage bearers that
// happen to contain two dots are caught downstream by ParseSigned.
func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// audienceMatchesResource compares an incoming audience claim list against an
// expected resource URL with trailing-slash tolerance. RFC 9728's canonical
// form uses a trailing slash, but upstream IdPs (and prior altinity-mcp
// metadata responses) sometimes emit the form without one — match both.
// Falls back to exact match if either side isn't a URL.
func audienceMatchesResource(claims []string, expected string) bool {
	expectedTrimmed := strings.TrimRight(strings.TrimSpace(expected), "/")
	for _, c := range claims {
		if c == expected {
			return true
		}
		if strings.TrimRight(strings.TrimSpace(c), "/") == expectedTrimmed {
			return true
		}
	}
	return false
}

// signatureAlgorithms lists the JWS algorithms accepted when parsing a
// compact-serialised JWT. Shared by parseAndVerifyExternalJWT and
// ValidateStrictJWT (oauth/strict_jwt.go) so both paths accept exactly the
// same signature algorithm set.
var signatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// jwtHeaderParseError classifies an error returned by parseAndFetchKeys'
// initial jwt.ParseSigned call (or its header-length check) as having
// originated before any signature verification — meaning its Error() text
// may embed raw, unverified, attacker-controlled JWT header content
// (malformed kid/alg/nonce/x5c type, unexpected alg, etc. — go-jose's
// rawHeader.sanitized() interpolates the raw header value into several
// distinct error shapes, and enumerating each one individually is how a
// one-pass review becomes four). ValidateStrictJWT must sanitize this
// whole class before returning; parseAndVerifyExternalJWT unwraps this
// wrapper immediately (see its own errors.As check) before returning to
// its existing callers, so their Error() text and their exact one-step
// errors.Unwrap() depth are both unaffected by this wrapper's existence.
type jwtHeaderParseError struct{ err error }

func (e *jwtHeaderParseError) Error() string { return e.err.Error() }
func (e *jwtHeaderParseError) Unwrap() error { return e.err }

// jwtParseFailedPrefix and jwtMissingHeaderText are the two fixed, literal
// error texts jwtHeaderParseError wraps (see parseAndFetchKeys below).
// parseAndVerifyExternalJWT deliberately strips the jwtHeaderParseError
// wrapper type before returning to its own callers (preserving the exact
// pre-jwtHeaderParseError object graph legacy callers depend on — see
// TestParseAndVerifyExternalJWTMalformedTokenUnwrapDepth in
// oauth/verifier_test.go, which asserts errors.As for *jwtHeaderParseError
// is false and that a single errors.Unwrap() lands directly on the raw
// go-jose error), so no structural (errors.Is/errors.As) sentinel survives
// on the error validator.go's legacy ValidateToken receives for this class.
// classifyLegacyValidationError (oauth/validator.go) instead matches on
// these fixed literal prefixes — safe because they are our own constant
// format-string text, never influenced by the attacker-controlled JWT
// header content that %w substitutes in afterward.
const (
	jwtParseFailedPrefix = "failed to parse signed JWT:"
	jwtMissingHeaderText = "missing JWT header"
)

// kidNotFoundError is the structural sentinel type for parseAndFetchKeys'
// "kid still missing after a JIT re-fetch" failure below. Its Error() text
// is fixed and never embeds the attacker-controlled `kid` JWT header value.
//
// It is returned as a single value (&kidNotFoundError{}), not wrapped
// alongside ErrTransient via fmt.Errorf("%w: %w", ...): Go represents a
// double-%w Errorf as Unwrap() []error, which would make a single
// errors.Unwrap() return nil instead of ErrTransient — an observable break
// in the legacy one-step-unwrap compatibility contract (see
// TestParseAndVerifyExternalJWTUnknownKid in oauth/verifier_test.go, which
// asserts errors.Unwrap(err) == ErrTransient directly). Instead
// kidNotFoundError.Unwrap() returns ErrTransient itself, keeping the chain
// exactly one step deep: kidNotFoundError -> ErrTransient. Callers detect
// this specific case structurally via isKidNotFoundError (oauth/strict_jwt.go,
// errors.As against *kidNotFoundError), not by matching on message text, so
// the classification stays structural even though the error's text is
// deliberately unremarkable.
type kidNotFoundError struct{}

func (e *kidNotFoundError) Error() string { return "no JWK found for token key id" }
func (e *kidNotFoundError) Unwrap() error { return ErrTransient }

// parseAndFetchKeys parses a compact-serialised JWT and resolves the JWKS
// candidate keys for verifying it: the entries matching the token's `kid`
// header (with a one-shot cache-bypass re-fetch on a kid miss, to tolerate
// IdP key rotation — see the inline comments below), or the full key set
// when the token carries no kid. This is the JWKS discovery/cache/
// kid-rotation machinery shared by parseAndVerifyExternalJWT and
// ValidateStrictJWT; neither the caller-facing issuer/audience/claim
// semantics nor any other behavior lives here.
func (v *Verifier) parseAndFetchKeys(ctx context.Context, token string) (*jwt.JSONWebToken, []jose.JSONWebKey, error) {
	jwksURI, err := v.resolveJWKSURL(ctx)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := jwt.ParseSigned(token, signatureAlgorithms)
	if err != nil {
		return nil, nil, &jwtHeaderParseError{err: fmt.Errorf("%s %w", jwtParseFailedPrefix, err)}
	}
	if len(parsed.Headers) == 0 {
		return nil, nil, &jwtHeaderParseError{err: errors.New(jwtMissingHeaderText)}
	}

	keySet, err := v.fetchJWKSet(ctx, jwksURI)
	if err != nil {
		return nil, nil, err
	}

	keys := keySet.Keys
	keyID := parsed.Headers[0].KeyID
	if keyID != "" {
		keys = keySet.Key(keyID)
		if len(keys) == 0 {
			// kid absent from the cached JWKS — the AS may have rotated its
			// signing key since the last fetch. Invalidate the cache and
			// retry once before giving up.
			v.invalidateJWKSCache()
			keySet, err = v.fetchJWKSet(ctx, jwksURI)
			if err != nil {
				return nil, nil, err
			}
			keys = keySet.Key(keyID)
			if len(keys) == 0 {
				// JIT-refetched JWKS still missing this kid. Could be a
				// forged token, but it could just as easily be an IdP CDN
				// that hasn't published the freshly-rotated key yet. The
				// sidecar treats this as transient so a multi-replica
				// rotation race doesn't pin a real token as bad on one
				// replica via the negative cache.
				//
				// The error text is FIXED and never embeds keyID: it is the
				// unverified `kid` JWT header value supplied by the caller
				// (arbitrary length/content, not yet authenticated by
				// anything), and legacy callers of parseAndVerifyExternalJWT
				// (oauth/validator.go's ValidateToken) log this error's
				// Error() text directly via log.Error().Err(err) — so it must
				// never carry attacker-controlled bytes. kidNotFoundError is
				// a structural marker (detected via errors.As, not by
				// matching on message text) that lets isKidNotFoundError
				// (oauth/strict_jwt.go) and logLegacyValidationFailure
				// (oauth/validator.go) both recognize this specific case,
				// while its Unwrap() keeps errors.Is(err, ErrTransient) —
				// and a single errors.Unwrap() landing on ErrTransient —
				// true.
				return nil, nil, &kidNotFoundError{}
			}
			// keyID is the unverified `kid` JWT header value supplied by the
			// caller (arbitrary length/content, not yet authenticated by
			// anything) — never log it. matched_keys is safe, non-sensitive
			// numeric context only.
			log.Info().Int("matched_keys", len(keys)).Msg("oauth: JWKS re-fetched after key rotation; new kid found")
		}
	}

	return parsed, keys, nil
}

// parseAndVerifyExternalJWT parses a compact-serialised JWT, fetches the JWKS
// for the configured issuer (with a one-shot kid-rotation refresh), and
// returns the validated claims. Issuer enforcement (singular config.Issuer)
// and audience enforcement (expectedAudience) both happen here, slash-
// normalised so a deployment whose issuer config omits the trailing slash
// matches a token whose `iss` includes it.
func (v *Verifier) parseAndVerifyExternalJWT(ctx context.Context, token, expectedAudience string) (*Claims, error) {
	parsed, keys, err := v.parseAndFetchKeys(ctx, token)
	if err != nil {
		var headerParseErr *jwtHeaderParseError
		if errors.As(err, &headerParseErr) {
			// Unwrap the jwtHeaderParseError classification wrapper before
			// returning: ValidateStrictJWT needs it (via errors.As) to detect
			// this pre-signature-verification error class, but this
			// function's existing callers predate that wrapper and must see
			// the exact same object graph as before it was introduced — a
			// single errors.Unwrap() on the returned error should land
			// directly on the wrapped fmt.Errorf, not on the wrapper itself.
			return nil, headerParseErr.err
		}
		return nil, err
	}

	expectedIssuer := strings.TrimRight(strings.TrimSpace(v.cfg.Issuer), "/")
	var (
		rawClaims         map[string]interface{}
		signatureVerified bool
		issuerRejected    bool
		audienceRejected  bool
	)
	for _, key := range keys {
		rawClaims = make(map[string]interface{})
		if err := parsed.Claims(key.Key, &rawClaims); err != nil {
			continue
		}
		signatureVerified = true
		claims := claimsFromRawClaims(rawClaims)
		gotIssuer := strings.TrimRight(strings.TrimSpace(claims.Issuer), "/")
		if expectedIssuer != "" && gotIssuer != expectedIssuer {
			issuerRejected = true
			continue
		}
		if expectedAudience != "" && !audienceMatchesResource(claims.Audience, expectedAudience) {
			audienceRejected = true
			continue
		}
		return claims, nil
	}
	if signatureVerified && (issuerRejected || audienceRejected) {
		return nil, ErrInvalidToken
	}

	return nil, fmt.Errorf("failed to verify JWT signature with discovered JWKs")
}
