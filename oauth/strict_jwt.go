package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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
	// comparisons. Zero means no tolerance (byte-for-byte "now").
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
func strictAudienceIntersects(tokenAudiences, expected []string) bool {
	expectedSet := make(map[string]bool, len(expected))
	for _, e := range expected {
		if e == "" {
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
	if nowUnix > expVal+leewaySecs {
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
// kid-rotation failures — is returned unchanged.
//
// The token string is never included in any returned error or log line.
func (v *Verifier) ValidateStrictJWT(ctx context.Context, token string, policy StrictJWTPolicy) (*Claims, error) {
	if !looksLikeJWT(token) {
		return nil, fmt.Errorf("%w: bearer is not a compact JWT", ErrInvalidToken)
	}
	if !hasNonEmptyExpectedAudience(policy.ExpectedAudiences) {
		return nil, fmt.Errorf("%w: at least one non-empty expected audience is required", ErrInvalidToken)
	}

	parsed, keys, err := v.parseAndFetchKeys(ctx, token)
	if err != nil {
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
