package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// TestValidateToken_OpaqueBearer_StrictJWTOnly exercises the StrictJWTOnly
// flag's effect on an opaque (non-JWT) bearer:
//   - Default (StrictJWTOnly=false): soft-pass — nil claims, nil error.
//   - StrictJWTOnly=true: hard reject with ErrInvalidToken.
func TestValidateToken_OpaqueBearer_StrictJWTOnly(t *testing.T) {
	t.Parallel()
	const opaque = "not-a-jwt-just-some-opaque-string"

	t.Run("soft-pass when StrictJWTOnly=false", func(t *testing.T) {
		v := NewVerifier(OAuthConfig{
			Enabled:       true,
			StrictJWTOnly: false,
		})
		claims, err := v.ValidateToken(context.Background(), opaque)
		require.NoError(t, err)
		require.Nil(t, claims)
	})

	t.Run("reject when StrictJWTOnly=true", func(t *testing.T) {
		v := NewVerifier(OAuthConfig{
			Enabled:       true,
			StrictJWTOnly: true,
		})
		claims, err := v.ValidateToken(context.Background(), opaque)
		require.Nil(t, claims)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrInvalidToken),
			"expected ErrInvalidToken, got %v", err)
	})
}

// swapLogger installs a fresh buffer-backed zerolog logger as the package's
// global logger, at trace level (so a Debug/Trace-level leak elsewhere on
// the path under test would also be caught, not just the Error-level line
// each test is nominally targeting), and returns a restore func. Tests using
// this must not run in parallel with each other (shared global state) — same
// pattern as TestJWKSRotationDoesNotLogKid (oauth/verifier_test.go) and the
// leakage tests in oauth/strict_jwt_test.go.
func swapLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	origLogger := zlog.Logger
	origLevel := zerolog.GlobalLevel()
	zlog.Logger = zerolog.New(&buf)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	t.Cleanup(func() {
		zlog.Logger = origLogger
		zerolog.SetGlobalLevel(origLevel)
	})
	return &buf
}

// TestValidateToken_LegacyUnknownKidDoesNotLeakKid proves that legacy
// ValidateToken (unlike ValidateStrictJWT, which already had its own
// dedicated leakage test) does not log the attacker-controlled `kid` JWT
// header value when parseAndFetchKeys' JIT re-fetch still can't find it
// (errKidNotFound, oauth/jwt.go). Before logLegacyValidationFailure existed,
// ValidateToken's log.Error().Err(err) logged this error's Error() text
// directly, which — before this fix — embedded the raw kid via
// fmt.Errorf("no JWK found for kid %q: %w", ...). Sabotage case: revert
// ValidateToken's log site to log.Error().Err(err) and this test fails.
func TestValidateToken_LegacyUnknownKidDoesNotLeakKid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	knownJWK := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "known-kid", Algorithm: "RS256", Use: "sig"}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{knownJWK}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	v := NewVerifier(OAuthConfig{
		Enabled: true,
		JWKSURL: server.URL + "/jwks",
	})

	// An email-like marker embedded in the kid header, guaranteed not to
	// appear anywhere else in the token or JWKS response.
	const kidMarker = "attacker-marker-legacy-kid@leaked-kid.example.com"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kidMarker),
	)
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]interface{}{
		"sub": "user-1",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	require.NoError(t, err)
	object, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := object.CompactSerialize()
	require.NoError(t, err)

	buf := swapLogger(t)

	claims, err := v.ValidateToken(context.Background(), token)
	require.Nil(t, claims)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrTransient), "expected ErrTransient, got %v", err)

	logged := buf.String()
	require.NotContains(t, logged, kidMarker, "ValidateToken must not log the attacker-controlled kid header value")
	require.NotContains(t, logged, token, "ValidateToken must not log the raw compact JWT")
}

// TestValidateToken_LegacyUnexpectedAlgDoesNotLeakHeader proves that legacy
// ValidateToken does not log raw JWT header content when jwt.ParseSigned
// rejects the token's `alg` before any signature verification
// (jwtHeaderParseError, oauth/jwt.go) — the header-parse classification
// branch of logLegacyValidationFailure. Sabotage case: revert ValidateToken's
// log site to log.Error().Err(err) and this test fails.
func TestValidateToken_LegacyUnexpectedAlgDoesNotLeakHeader(t *testing.T) {
	v := NewVerifier(OAuthConfig{
		Enabled: true,
		JWKSURL: "https://jwks.invalid/jwks",
	})

	// An email-like marker used as the alg value itself, guaranteed not to
	// appear anywhere else in the error text.
	const algMarker = "attacker-marker-legacy-alg@leaked-alg.example.com"
	header := map[string]interface{}{"alg": algMarker, "typ": "JWT"}
	claims := map[string]interface{}{
		"sub": "user-1",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := rawCompactJWTWithHeader(t, header, claims)

	buf := swapLogger(t)

	claimsOut, err := v.ValidateToken(context.Background(), token)
	require.Nil(t, claimsOut)
	require.Error(t, err)
	// Note: what ValidateToken RETURNS is unchanged by this fix (the
	// compatibility contract at jwt.go's jwtParseFailedPrefix doc comment) —
	// err.Error() here still legitimately contains algMarker, same as
	// before. Only the LOG is required to be safe; that's asserted below.

	logged := buf.String()
	require.NotContains(t, logged, algMarker, "ValidateToken must not log the attacker-controlled alg header value")
	require.NotContains(t, logged, token, "ValidateToken must not log the raw compact JWT")
	require.Contains(t, logged, "jwt header rejected", "the fixed header-rejection message must still be logged")
}

// TestValidateClaims_AudienceMismatchDoesNotLeakClaimValues proves that
// validateClaims' audience-mismatch log line no longer logs the token's own
// audience claim values — only a count — while still returning
// ErrInvalidToken. Unit-tests validateClaims directly (same pattern as
// TestValidateClaims in oauth/verifier_test.go), since parseAndVerifyExternalJWT
// already enforces this same audience check ahead of validateClaims on
// ValidateToken's actual call path (see validateClaims' own "Issuer
// enforcement... Re-validating here would duplicate the check" comment —
// the audience branch is equally unreachable through ValidateToken itself,
// but stays defense-in-depth and is exercised directly here, as
// TestValidateClaims already does for its other assertions). A
// marker-bearing audience value would previously have appeared via the
// removed Strs("got", claims.Audience) field.
func TestValidateClaims_AudienceMismatchDoesNotLeakClaimValues(t *testing.T) {
	v := NewVerifier(OAuthConfig{Audience: "expected-audience"})

	const audMarker = "attacker-marker-legacy-aud@leaked-aud.example.com"
	buf := swapLogger(t)

	claims, err := v.validateClaims(&Claims{Audience: []string{audMarker}})
	require.Nil(t, claims)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInvalidToken), "expected ErrInvalidToken, got %v", err)

	logged := buf.String()
	require.NotContains(t, logged, audMarker, "validateClaims must not log the token's own audience claim value")
	require.Contains(t, logged, "got_count", "a count should still be logged for diagnosis")
}

// TestValidateClaims_MissingScopeDoesNotLeakClaimValues proves that
// validateClaims' missing-required-scope log line no longer logs the
// token's own scope claim values — only a count — while still returning
// ErrInsufficientScopes.
func TestValidateClaims_MissingScopeDoesNotLeakClaimValues(t *testing.T) {
	v := NewVerifier(OAuthConfig{RequiredScopes: []string{"admin"}})

	const scopeMarker = "attacker-marker-legacy-scope-leaked"
	buf := swapLogger(t)

	claims, err := v.validateClaims(&Claims{Scopes: []string{scopeMarker}})
	require.Nil(t, claims)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInsufficientScopes), "expected ErrInsufficientScopes, got %v", err)

	logged := buf.String()
	require.NotContains(t, logged, scopeMarker, "validateClaims must not log the token's own scope claim value")
	require.Contains(t, logged, "got_count", "a count should still be logged for diagnosis")
}
