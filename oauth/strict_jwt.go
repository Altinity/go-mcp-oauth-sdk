package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// int64MinAsFloat and int64MaxAsFloat are the safe float64 bounds for
// conversion to int64. 9223372036854775808.0 is 2^63, the correct strict
// upper bound: note that float64(math.MaxInt64) itself rounds UP to 2^63 due
// to float64's limited mantissa precision, so comparing against
// float64(math.MaxInt64) directly would wrongly admit the overflow boundary
// value. -9223372036854775808.0 is exactly representable (it's -2^63) and is
// math.MinInt64, so it remains the correct (inclusive) lower bound.
const (
	int64MinAsFloat = -9223372036854775808.0 // -2^63, exactly math.MinInt64
	int64MaxAsFloat = 9223372036854775808.0  // 2^63, exclusive upper bound
)

// StrictJWTPolicy configures ValidateStrictJWT's byte-exact issuer/audience
// checks and its expiry/not-before/issued-at tolerance. Unlike ValidateToken
// (which soft-passes opaque bearers and slash-normalises issuer/audience
// matching for backward compatibility with existing deployments),
// ValidateStrictJWT never soft-passes and never normalises: every field here
// is enforced literally.
type StrictJWTPolicy struct {
	// ExpectedIssuer, when non-empty, must equal the token's raw `iss`
	// claim exactly — no trailing-slash or other normalization.
	ExpectedIssuer string
	// ExpectedAudiences must contain at least one non-empty entry. The
	// token's `aud` claim (string or array-of-strings form) must contain at
	// least one byte-exact match against this list.
	ExpectedAudiences []string
	// Leeway bounds the clock-skew tolerance applied to exp/nbf/iat
	// comparisons. Zero means no tolerance (byte-for-byte "now"). Leeway
	// operates at whole-second granularity — any sub-second remainder is
	// truncated — matching the NumericDate/Unix-timestamp convention used
	// throughout this package (e.g. validateClaims in oauth/validator.go).
	// Leeway must not be negative: ValidateStrictJWT rejects a negative
	// Leeway as an invalid policy before doing any JWKS work, since it could
	// otherwise integer-overflow the expiry/not-before/issued-at comparisons
	// in validateStrictRawClaims when combined with an extreme claim value.
	Leeway time.Duration
	// RequiredScopes, when non-empty, must all be present in the token's
	// projected Claims.Scopes (checked via HasRequiredScopes).
	RequiredScopes []string
}

// hasNonEmptyExpectedAudience reports whether audiences contains at least
// one non-whitespace entry. An empty or all-empty ExpectedAudiences list is
// a caller configuration error (point 5 of the strict-JWT contract) — it is
// never treated as "no audience check".
func hasNonEmptyExpectedAudience(audiences []string) bool {
	for _, a := range audiences {
		if strings.TrimSpace(a) != "" {
			return true
		}
	}
	return false
}

// strictAudienceClaim reads the raw `aud` claim directly from unprojected
// claims: only a JSON string or an array whose every element is a string is
// accepted. Any other shape — including an array with a mixed-type element —
// is a validation error, never a partial match against whatever happened to
// parse (unlike claimsFromRawClaims, which silently drops non-string
// elements; the strict path must not reuse that lossy projection).
func strictAudienceClaim(rawClaims map[string]interface{}) ([]string, error) {
	switch aud := rawClaims["aud"].(type) {
	case string:
		return []string{aud}, nil
	case []interface{}:
		out := make([]string, 0, len(aud))
		for _, a := range aud {
			s, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("%w: aud claim contains a non-string element", ErrInvalidToken)
			}
			out = append(out, s)
		}
		return out, nil
	case nil:
		return nil, fmt.Errorf("%w: missing aud claim", ErrInvalidToken)
	default:
		return nil, fmt.Errorf("%w: malformed aud claim", ErrInvalidToken)
	}
}

// strictAudienceIntersects reports whether tokenAudiences and expected share
// at least one byte-exact entry. No substring/prefix matching, no slash
// trimming — unlike audienceMatchesResource, which is intentionally
// trailing-slash tolerant for parseAndVerifyExternalJWT's existing callers.
//
// Entries that are empty or whitespace-only are skipped when building the
// expected set, mirroring hasNonEmptyExpectedAudience's definition of
// "empty" exactly. The two functions must agree: hasNonEmptyExpectedAudience
// decides whether a policy is valid at all (it requires at least one
// non-whitespace entry), and if it disagreed with this filter, a policy like
// ExpectedAudiences: []string{"api-1", "   "} would be accepted as valid
// (thanks to "api-1") while a token whose only `aud` value is "   " would
// then wrongly match against the unfiltered "   " entry here.
func strictAudienceIntersects(tokenAudiences, expected []string) bool {
	expectedSet := make(map[string]bool, len(expected))
	for _, e := range expected {
		if strings.TrimSpace(e) == "" {
			continue
		}
		expectedSet[e] = true
	}
	for _, a := range tokenAudiences {
		if expectedSet[a] {
			return true
		}
	}
	return false
}

// strictNumericClaim inspects a raw claim value expected to be a Unix
// timestamp, accepting the same float64/json.Number representations
// claimsFromRawClaims accepts elsewhere in this package. present reports
// whether the key exists at all; malformed reports whether it exists but is
// neither representation — callers need to tell "absent" apart from
// "present but garbage" since the strict-JWT contract treats a malformed
// nbf/iat as an error rather than as absent (point 10, 11).
func strictNumericClaim(rawClaims map[string]interface{}, key string) (value int64, present bool, malformed bool) {
	raw, exists := rawClaims[key]
	if !exists {
		return 0, false, false
	}
	switch n := raw.(type) {
	case float64:
		// Converting an out-of-range float64 to int64 via a bare int64(n) is
		// implementation-defined in Go (it can saturate to math.MaxInt64 on
		// some architectures, or wrap to math.MinInt64 on others). A
		// well-typed but absurdly large exp/nbf/iat (e.g. 1e30) could
		// therefore silently invert the intended comparison depending on the
		// build architecture. Reject anything outside the safe int64 range
		// as malformed instead of converting it.
		if n < int64MinAsFloat || n >= int64MaxAsFloat {
			return 0, true, true
		}
		return int64(n), true, false
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, true, true
		}
		return i, true, false
	default:
		return 0, true, true
	}
}

// validateStrictRawClaims applies the strict-JWT contract's issuer/
// audience/exp/nbf/iat checks (points 4-11) directly against the unprojected
// claims map, before any lossy projection happens. It must run before
// claimsFromRawClaims is used for anything but the final return value.
func validateStrictRawClaims(rawClaims map[string]interface{}, policy StrictJWTPolicy, now time.Time) error {
	if policy.ExpectedIssuer != "" {
		issRaw, ok := rawClaims["iss"]
		issStr, isStr := issRaw.(string)
		if !ok || !isStr || issStr != policy.ExpectedIssuer {
			return fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
		}
	}

	tokenAudiences, err := strictAudienceClaim(rawClaims)
	if err != nil {
		return err
	}
	if !strictAudienceIntersects(tokenAudiences, policy.ExpectedAudiences) {
		return fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}

	leewaySecs := int64(policy.Leeway / time.Second)
	nowUnix := now.Unix()

	expVal, expPresent, expMalformed := strictNumericClaim(rawClaims, "exp")
	if !expPresent || expMalformed {
		return fmt.Errorf("%w: missing or malformed exp claim", ErrInvalidToken)
	}
	// Compare as (nowUnix-leewaySecs) > expVal rather than nowUnix >
	// expVal+leewaySecs. expVal is an attacker-controlled claim value, and
	// strictNumericClaim's range check admits the full safe-int64 range —
	// including the extreme boundary math.MinInt64 — so adding leewaySecs to
	// it can integer-overflow and wrap around, silently flipping this
	// comparison (a fail-open expiry bypass). nowUnix (wall-clock "now") and
	// leewaySecs (bounded by time.Duration's own range, and by
	// ValidateStrictJWT rejecting a negative Leeway) are both sane,
	// non-extreme magnitudes, so their difference can't overflow. expVal
	// itself is never used in arithmetic here — only in comparison — so this
	// is safe regardless of how extreme expVal is. This is defense in depth:
	// ValidateStrictJWT's negative-Leeway rejection already prevents the
	// specific overflow direction that's exploitable, but this comparison
	// stays overflow-safe on its own regardless of that input validation.
	if nowUnix-leewaySecs > expVal {
		return ErrTokenExpired
	}

	if nbfVal, nbfPresent, nbfMalformed := strictNumericClaim(rawClaims, "nbf"); nbfPresent {
		if nbfMalformed {
			return fmt.Errorf("%w: malformed nbf claim", ErrInvalidToken)
		}
		if nowUnix+leewaySecs < nbfVal {
			return fmt.Errorf("%w: token not yet valid", ErrInvalidToken)
		}
	}

	if iatVal, iatPresent, iatMalformed := strictNumericClaim(rawClaims, "iat"); iatPresent {
		if iatMalformed {
			return fmt.Errorf("%w: malformed iat claim", ErrInvalidToken)
		}
		if iatVal > nowUnix+leewaySecs {
			return fmt.Errorf("%w: token issued in the future", ErrInvalidToken)
		}
	}

	return nil
}

// kidNotFoundErrorPrefix is the fixed, non-attacker-controlled prefix of the
// error parseAndFetchKeys (oauth/jwt.go) returns when a JWKS re-fetch still
// can't find the token's kid. Matching on this fixed prefix (rather than on
// the error's dynamic %q-quoted kid suffix, which is exactly the part that
// must never reach ValidateStrictJWT's caller) lets isKidNotFoundError detect
// this specific case without hardcoding, or otherwise reproducing, any
// attacker-controlled content.
const kidNotFoundErrorPrefix = "no JWK found for kid "

// isKidNotFoundError reports whether err is parseAndFetchKeys' "no JWK found
// for kid %q" error — the one ErrTransient failure out of parseAndFetchKeys
// that embeds the attacker-controlled `kid` JWT header value in its text.
func isKidNotFoundError(err error) bool {
	return errors.Is(err, ErrTransient) && strings.HasPrefix(err.Error(), kidNotFoundErrorPrefix)
}

// ValidateStrictJWT validates token against policy with byte-exact issuer/
// audience matching and mandatory exp, in contrast to ValidateToken's
// soft-pass-on-opaque-bearer and trailing-slash-tolerant behavior. It never
// returns (nil, nil): an opaque (non-JWT) bearer is always a hard error
// here, never a soft-pass.
//
// JWKS discovery, caching, and kid-rotation reuse the same machinery
// parseAndVerifyExternalJWT relies on (parseAndFetchKeys in oauth/jwt.go);
// this function adds no separate key-fetching path. Any error from that
// machinery — including the ErrTransient-wrapped network/discovery/
// kid-rotation failures — is returned unchanged, with two exceptions, both
// of which may embed attacker-controlled (unverified, pre-signature) JWT
// header content in their Error() text and are sanitized to a fixed message
// before reaching this function's caller:
//
//   - The "no JWK found for kid %q" case embeds the token's `kid` header
//     value. Stripped below — see the isKidNotFoundError check — while
//     errors.Is(err, ErrTransient) still holds.
//   - Any error from parseAndFetchKeys' initial jwt.ParseSigned call or its
//     header-length check — before any JWKS fetch or kid lookup — is wrapped
//     in a *jwtHeaderParseError (oauth/jwt.go). go-jose's header-sanitization
//     logic interpolates raw, unverified header content into several
//     distinct error shapes here (unexpected `alg`, malformed `kid`/`nonce`/
//     `x5c` type, etc.), so this is handled as one class via errors.As rather
//     than enumerated case by case. Stripped below and reclassified as
//     ErrInvalidToken, since a parse failure is not one of parseAndFetchKeys'
//     JWKS-fetch/kid-rotation transient failures.
//
// The token string is never included in any returned error or log line.
func (v *Verifier) ValidateStrictJWT(ctx context.Context, token string, policy StrictJWTPolicy) (*Claims, error) {
	if !looksLikeJWT(token) {
		return nil, fmt.Errorf("%w: bearer is not a compact JWT", ErrInvalidToken)
	}
	if !hasNonEmptyExpectedAudience(policy.ExpectedAudiences) {
		return nil, fmt.Errorf("%w: at least one non-empty expected audience is required", ErrInvalidToken)
	}
	if policy.Leeway < 0 {
		// A negative Leeway is a caller configuration error, not an
		// attacker-controlled input, but it's rejected up front (before any
		// JWKS work) for the same reason an empty ExpectedAudiences is: it
		// would otherwise let leewaySecs go negative in
		// validateStrictRawClaims, which — combined with an extreme (but
		// currently-accepted-as-a-boundary-value) exp/nbf/iat claim like
		// math.MinInt64 — could integer-overflow the expiry/not-before/
		// issued-at arithmetic there and silently flip a rejection into an
		// acceptance. See validateStrictRawClaims' exp comparison, which is
		// also hardened independently of this check (defense in depth).
		return nil, fmt.Errorf("%w: leeway must not be negative", ErrInvalidToken)
	}

	parsed, keys, err := v.parseAndFetchKeys(ctx, token)
	if err != nil {
		var headerParseErr *jwtHeaderParseError
		if errors.As(err, &headerParseErr) {
			// err originated in parseAndFetchKeys' initial jwt.ParseSigned
			// call or its header-length check — i.e. before any JWKS fetch
			// or kid lookup — so its Error() text may embed raw, unverified,
			// attacker-controlled JWT header content (unexpected `alg`,
			// malformed `kid` type, etc. — see jwtHeaderParseError in
			// oauth/jwt.go). Unlike parseAndVerifyExternalJWT's callers (left
			// unchanged — this check only affects what ValidateStrictJWT
			// itself returns), ValidateStrictJWT must never let that
			// attacker-controlled header data reach its own returned-error
			// surface. This is a parse-time rejection, not one of
			// parseAndFetchKeys' JWKS-fetch/kid-rotation ErrTransient
			// failures, so it's classified as ErrInvalidToken rather than
			// ErrTransient.
			return nil, fmt.Errorf("%w: unable to parse or validate JWT header", ErrInvalidToken)
		}
		if isKidNotFoundError(err) {
			// parseAndFetchKeys' "no JWK found for kid %q" error (oauth/jwt.go)
			// embeds the raw, unverified `kid` JWT header value in its text.
			// That's fine for parseAndVerifyExternalJWT's existing callers
			// (left unchanged — this check only affects what ValidateStrictJWT
			// itself returns), but ValidateStrictJWT must never let
			// attacker-controlled header data reach its own returned-error
			// surface. Sanitize just this case to a fixed message, preserving
			// errors.Is(err, ErrTransient); other ErrTransient failures from
			// this step (network/discovery/JWKS-endpoint errors) don't embed
			// attacker data and are returned unchanged.
			return nil, fmt.Errorf("failed to resolve a JWK for the token's key id: %w", ErrTransient)
		}
		return nil, err
	}

	now := time.Now()
	for _, key := range keys {
		rawClaims := make(map[string]interface{})
		if err := parsed.Claims(key.Key, &rawClaims); err != nil {
			// Signature didn't verify against this candidate key; try the
			// next one (relevant when the JWKS has multiple keys and the
			// token carries no kid).
			continue
		}

		// Signature verified against this key before any claim is trusted
		// (point 3) — only now do we inspect claims.
		if err := validateStrictRawClaims(rawClaims, policy, now); err != nil {
			return nil, err
		}

		claims := claimsFromRawClaims(rawClaims)
		if len(policy.RequiredScopes) > 0 && !HasRequiredScopes(claims.Scopes, policy.RequiredScopes) {
			return nil, ErrInsufficientScopes
		}
		return claims, nil
	}

	return nil, fmt.Errorf("failed to verify JWT signature with discovered JWKs")
}
