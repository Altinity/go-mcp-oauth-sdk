package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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

// strictTestIdP is a minimal httptest-backed JWKS server plus a signer for
// ValidateStrictJWT test tokens. Independent of any shared fixture, per this
// repo's convention (see verifier_test.go's TestParseAndVerifyExternalJWTUnknownKid).
type strictTestIdP struct {
	t        *testing.T
	server   *httptest.Server
	verifier *Verifier
	key      *rsa.PrivateKey
	kid      string
}

const strictTestKid = "strict-test-kid"

func newStrictTestIdP(t *testing.T) *strictTestIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: strictTestKid, Algorithm: "RS256", Use: "sig"},
		}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	v := NewVerifier(OAuthConfig{JWKSURL: server.URL + "/jwks"})
	return &strictTestIdP{t: t, server: server, verifier: v, key: key, kid: strictTestKid}
}

// sign marshals claims and signs them with idp's key under the given kid
// header — a distinct kid parameter (rather than always idp.kid) lets the
// "invalid signature" test put a kid on the token that matches an entry in
// the JWKS while actually signing with a different, unregistered key.
func signRawClaimsWithKey(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := obj.CompactSerialize()
	require.NoError(t, err)
	return token
}

func (idp *strictTestIdP) sign(claims map[string]interface{}) string {
	return signRawClaimsWithKey(idp.t, idp.key, idp.kid, claims)
}

// baseClaims returns a well-formed claim set (iss/aud/exp/iat/sub) that
// individual tests mutate to exercise one specific rejection.
func baseClaims(issuer string, aud interface{}, now time.Time) map[string]interface{} {
	return map[string]interface{}{
		"sub": "user-1",
		"iss": issuer,
		"aud": aud,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
}

func TestValidateStrictJWT_Success(t *testing.T) {
	t.Parallel()

	t.Run("string aud", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		token := idp.sign(baseClaims("https://issuer.example.com", "api-1", now))

		claims, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedIssuer:    "https://issuer.example.com",
			ExpectedAudiences: []string{"api-1"},
		})
		require.NoError(t, err)
		require.Equal(t, "user-1", claims.Subject)
	})

	t.Run("array aud intersects", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		token := idp.sign(baseClaims("https://issuer.example.com", []interface{}{"api-1", "api-2"}, now))

		claims, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedIssuer:    "https://issuer.example.com",
			ExpectedAudiences: []string{"api-2", "api-3"},
		})
		require.NoError(t, err)
		require.Equal(t, "user-1", claims.Subject)
	})

	t.Run("required scopes satisfied", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["scope"] = "read write"
		token := idp.sign(claims)

		got, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedIssuer:    "https://issuer.example.com",
			ExpectedAudiences: []string{"api-1"},
			RequiredScopes:    []string{"read"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{"read", "write"}, got.Scopes)
	})

	t.Run("expired past leeway-adjusted deadline still within leeway succeeds", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["exp"] = now.Add(-30 * time.Second).Unix()
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
			Leeway:            time.Minute,
		})
		require.NoError(t, err)
	})
}

// TestValidateStrictJWT_NeverSoftPasses proves the strict path never
// returns (nil, nil) for an opaque bearer — the sabotage case: remove the
// looksLikeJWT check and this starts returning nil error.
func TestValidateStrictJWT_NeverSoftPasses(t *testing.T) {
	t.Parallel()
	idp := newStrictTestIdP(t)
	claims, err := idp.verifier.ValidateStrictJWT(context.Background(), "not-a-jwt-opaque-bearer", StrictJWTPolicy{
		ExpectedAudiences: []string{"api-1"},
	})
	require.Error(t, err)
	require.Nil(t, claims)
}

func TestValidateStrictJWT_AudienceRejections(t *testing.T) {
	t.Parallel()

	t.Run("no intersection fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		token := idp.sign(baseClaims("https://issuer.example.com", "api-1", now))

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-2"},
		})
		require.Error(t, err)
	})

	t.Run("empty ExpectedAudiences fails without even fetching JWKS", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		token := idp.sign(baseClaims("https://issuer.example.com", "api-1", now))

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: nil,
		})
		require.Error(t, err)

		_, err = idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"", "   "},
		})
		require.Error(t, err)
	})

	// Sabotage case: reuse claimsFromRawClaims's lossy aud projection instead
	// of the raw type-switch — the bad element would silently drop and
	// "good-aud" would wrongly match. This test regresses under that
	// sabotage.
	t.Run("mixed-type aud array fails, does not partially match", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", []interface{}{"good-aud", 12345}, now)
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"good-aud"},
		})
		require.Error(t, err, "malformed aud must not partially match on the well-formed element")
	})

	t.Run("missing aud claim fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		delete(claims, "aud")
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
	})

	// Sabotage case: drop strictAudienceIntersects' whitespace-only-entry
	// skip (or diverge it from hasNonEmptyExpectedAudience's definition of
	// "empty") and a token whose only aud value is three spaces would wrongly
	// match against the unfiltered "   " policy entry, even though it never
	// matches "api-1" — this test must go red under that sabotage.
	t.Run("whitespace-only audience entry does not match", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		// Token's aud is whitespace-only, and deliberately does NOT include
		// "api-1" — the real entry in the policy below — so a pass here can
		// only be explained by the "   " entry wrongly matching.
		token := idp.sign(baseClaims("https://issuer.example.com", "   ", now))

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1", "   "},
		})
		require.Error(t, err, "a whitespace-only aud claim must not match a whitespace-only policy entry")
	})

	// Sabotage case: reintroduce audienceMatchesResource-style trailing-slash
	// normalization into strictAudienceIntersects and this test must go red —
	// unlike parseAndVerifyExternalJWT's issuer/audience matching, the strict
	// path is byte-exact and must reject a trailing-slash-only difference.
	t.Run("trailing-slash-only audience difference fails (byte-exact, unlike audienceMatchesResource)", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		token := idp.sign(baseClaims("https://issuer.example.com", "https://api.example.com/", now))

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"https://api.example.com"},
		})
		require.Error(t, err, "byte-exact audience comparison must reject a trailing-slash-only difference")
	})
}

func TestValidateStrictJWT_SignatureAndIssuer(t *testing.T) {
	t.Parallel()

	t.Run("invalid signature fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		now := time.Now()
		// Signed with a key that is NOT the one published under this kid in
		// the JWKS — parsed.Claims must fail signature verification.
		token := signRawClaimsWithKey(t, wrongKey, idp.kid, baseClaims("https://issuer.example.com", "api-1", now))

		_, err = idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
	})

	t.Run("wrong issuer fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		token := idp.sign(baseClaims("https://other-issuer.example.com", "api-1", now))

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedIssuer:    "https://issuer.example.com",
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
	})

	// Sabotage case: reuse the trailing-slash-normalized issuer comparison
	// from parseAndVerifyExternalJWT instead of a byte-exact one — this
	// test would then wrongly pass.
	t.Run("trailing-slash-only issuer difference fails (byte-exact, unlike parseAndVerifyExternalJWT)", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		token := idp.sign(baseClaims("https://issuer.example.com/", "api-1", now))

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedIssuer:    "https://issuer.example.com",
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err, "byte-exact issuer comparison must reject a trailing-slash-only difference")
	})
}

func TestValidateStrictJWT_Expiry(t *testing.T) {
	t.Parallel()

	t.Run("missing exp fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		delete(claims, "exp")
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
	})

	t.Run("non-numeric exp fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["exp"] = "not-a-number"
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
	})

	// Sabotage case: convert the raw float64 exp via a bare int64(n) instead
	// of range-checking first. A bare conversion is implementation-defined
	// for an out-of-range float64 (it can saturate to math.MaxInt64 on some
	// architectures, or wrap around to a negative number on others) — either
	// way an absurdly large exp like 1e30 must never be silently accepted or
	// misinterpreted as already-expired/not-expired by accident. It must be
	// rejected outright as malformed.
	t.Run("absurdly large exp fails as malformed, not silently converted", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["exp"] = 1e30
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
		require.False(t, errors.Is(err, ErrTokenExpired), "an out-of-range exp must be rejected as malformed, not classified as expired")
	})

	t.Run("expired beyond leeway fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["exp"] = now.Add(-2 * time.Minute).Unix()
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
			Leeway:            time.Minute,
		})
		require.ErrorIs(t, err, ErrTokenExpired)
	})
}

func TestValidateStrictJWT_NotBeforeAndIssuedAt(t *testing.T) {
	t.Parallel()

	t.Run("nbf in future beyond leeway fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["nbf"] = now.Add(2 * time.Minute).Unix()
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
			Leeway:            time.Minute,
		})
		require.Error(t, err)
	})

	t.Run("nbf within leeway succeeds", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["nbf"] = now.Add(30 * time.Second).Unix()
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
			Leeway:            time.Minute,
		})
		require.NoError(t, err)
	})

	t.Run("malformed nbf fails (not treated as absent)", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["nbf"] = "garbage"
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
	})

	t.Run("iat in future beyond leeway fails", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["iat"] = now.Add(2 * time.Minute).Unix()
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
			Leeway:            time.Minute,
		})
		require.Error(t, err)
	})

	t.Run("malformed iat fails (not treated as absent)", func(t *testing.T) {
		t.Parallel()
		idp := newStrictTestIdP(t)
		now := time.Now()
		claims := baseClaims("https://issuer.example.com", "api-1", now)
		claims["iat"] = "garbage"
		token := idp.sign(claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
			ExpectedAudiences: []string{"api-1"},
		})
		require.Error(t, err)
	})
}

func TestValidateStrictJWT_RequiredScopes(t *testing.T) {
	t.Parallel()
	idp := newStrictTestIdP(t)
	now := time.Now()
	claims := baseClaims("https://issuer.example.com", "api-1", now)
	claims["scope"] = "read"
	token := idp.sign(claims)

	_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
		ExpectedAudiences: []string{"api-1"},
		RequiredScopes:    []string{"admin"},
	})
	require.ErrorIs(t, err, ErrInsufficientScopes)
}

// TestValidateStrictJWT_KidNotFoundDoesNotLeakKid proves that when
// parseAndFetchKeys' "no JWK found for kid %q" error (oauth/jwt.go) bubbles
// up through ValidateStrictJWT, the attacker-controlled (unverified,
// pre-signature) `kid` header value it embeds never reaches
// ValidateStrictJWT's own returned error — even though errors.Is(err,
// ErrTransient) must still hold, since that's how callers like the
// ch-jwt-verify sidecar distinguish "transient, don't negative-cache" from a
// hard rejection. Sabotage case: forward parseAndFetchKeys' error unchanged
// from ValidateStrictJWT and this test fails.
func TestValidateStrictJWT_KidNotFoundDoesNotLeakKid(t *testing.T) {
	t.Parallel()
	idp := newStrictTestIdP(t)
	now := time.Now()

	// An email-like marker embedded in the kid header, guaranteed not to
	// appear anywhere else in the token, claims, or JWKS response.
	const kidMarker = "attacker-marker-user@leaked-kid.example.com"
	token := signRawClaimsWithKey(t, idp.key, kidMarker, baseClaims("https://issuer.example.com", "api-1", now))

	_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
		ExpectedAudiences: []string{"api-1"},
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrTransient), "expected ErrTransient, got %v", err)
	require.NotContains(t, err.Error(), kidMarker, "ValidateStrictJWT must not leak the attacker-controlled kid header value in its own returned error")
}

// TestValidateStrictJWT_JWKSFailureWrapsTransient proves point 13: a
// JWKS-fetch failure (upstream 5xx here) surfaces as ErrTransient, reusing
// fetchJWKSet's existing error path rather than a bespoke one.
func TestValidateStrictJWT_JWKSFailureWrapsTransient(t *testing.T) {
	t.Parallel()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	v := NewVerifier(OAuthConfig{JWKSURL: mockServer.URL + "/jwks"})

	// A well-formed (but arbitrarily signed) token — the failure must come
	// from the JWKS fetch, not from token parsing.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	token := signRawClaimsWithKey(t, key, "any-kid", baseClaims("https://issuer.example.com", "api-1", now))

	_, err = v.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
		ExpectedAudiences: []string{"api-1"},
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrTransient), "expected ErrTransient, got %v", err)
}

// TestValidateStrictJWT_NoTokenLeakage is the marker-based test from the
// invariant map: inject a unique marker into the raw token and assert it
// never surfaces in a returned error string, nor in anything logged via the
// package's zerolog logger, across several distinct failure paths. Sabotage
// case: log/format the token on any of these paths and this test fails.
func TestValidateStrictJWT_NoTokenLeakage(t *testing.T) {
	idp := newStrictTestIdP(t)
	now := time.Now()

	var logBuf bytes.Buffer
	origLogger := zlog.Logger
	zlog.Logger = zerolog.New(&logBuf)
	defer func() { zlog.Logger = origLogger }()

	scenarios := []struct {
		name   string
		claims map[string]interface{}
		policy StrictJWTPolicy
	}{
		{
			name:   "wrong issuer",
			claims: baseClaims("https://wrong-issuer.example.com", "api-1", now),
			policy: StrictJWTPolicy{ExpectedIssuer: "https://issuer.example.com", ExpectedAudiences: []string{"api-1"}},
		},
		{
			name: "expired",
			claims: func() map[string]interface{} {
				c := baseClaims("https://issuer.example.com", "api-1", now)
				c["exp"] = now.Add(-time.Hour).Unix()
				return c
			}(),
			policy: StrictJWTPolicy{ExpectedAudiences: []string{"api-1"}},
		},
		{
			name:   "no audience intersection",
			claims: baseClaims("https://issuer.example.com", "api-1", now),
			policy: StrictJWTPolicy{ExpectedAudiences: []string{"other-api"}},
		},
	}

	for _, sc := range scenarios {
		// Embed a per-token marker in a claim so a bug that formats "the
		// claims" or "the payload" into an error would also be caught, not
		// just a bug that formats the raw compact-serialized token.
		marker := "TOKEN-MARKER-" + sc.name
		sc.claims["jti"] = marker
		token := idp.sign(sc.claims)

		_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, sc.policy)
		require.Error(t, err)
		require.NotContains(t, err.Error(), marker)
		require.NotContains(t, err.Error(), token)
		// The marker claim is base64url-encoded as part of the compact JWT,
		// so it never appears as a literal substring of token — checking
		// only for the marker in the log buffer would miss a sabotage that
		// logs the raw compact token string directly. Check per-iteration,
		// while we still know which token produced this scenario's log
		// output, that the log buffer never contains it either.
		require.NotContains(t, logBuf.String(), token, "scenario %q must not log the raw compact JWT", sc.name)
	}

	logged := logBuf.String()
	require.NotContains(t, logged, "TOKEN-MARKER-")
}

// b64urlNoPad matches the unpadded base64url encoding compact JWT segments
// use.
func b64urlNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// rawCompactJWTWithHeader hand-constructs a compact-serialized JWT with an
// arbitrary header map, without going through a jose.Signer (which only
// accepts header values from its own known-shape enums and would refuse to
// build a token with attacker-marker content in them). go-jose's
// jwt.ParseSigned sanitizes and validates the header before any signature
// verification happens, so the third segment's content is irrelevant here —
// it never gets checked once the header itself is already rejected.
func rawCompactJWTWithHeader(t *testing.T, header map[string]interface{}, claims map[string]interface{}) string {
	t.Helper()
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return b64urlNoPad(headerBytes) + "." + b64urlNoPad(payload) + "." + b64urlNoPad([]byte("not-a-real-signature"))
}

// rawCompactJWTWithAlg hand-constructs a compact-serialized JWT whose header
// carries an arbitrary alg value. See rawCompactJWTWithHeader.
func rawCompactJWTWithAlg(t *testing.T, alg string, claims map[string]interface{}) string {
	t.Helper()
	return rawCompactJWTWithHeader(t, map[string]interface{}{"alg": alg, "typ": "JWT"}, claims)
}

// TestValidateStrictJWT_UnexpectedAlgDoesNotLeakAlg proves that when a
// token's header `alg` isn't in signatureAlgorithms, go-jose's
// *jose.ErrUnexpectedSignatureAlgorithm — which embeds that raw,
// attacker-controlled (unverified, pre-signature) alg value in its Error()
// text — never reaches ValidateStrictJWT's own returned error, nor anything
// logged via the package's zerolog logger (same buffer-swap pattern as
// TestValidateStrictJWT_NoTokenLeakage — not run in parallel with other
// tests for the same reason: it swaps the shared global zerolog logger).
// Sabotage case: forward parseAndFetchKeys' wrapped parse error unchanged
// from ValidateStrictJWT (i.e. delete the isUnexpectedSignatureAlgorithmError
// check) and this test fails; sabotage case for the log assertions: log the
// raw token or the header value on this path and they fail too.
func TestValidateStrictJWT_UnexpectedAlgDoesNotLeakAlg(t *testing.T) {
	idp := newStrictTestIdP(t)
	now := time.Now()

	var logBuf bytes.Buffer
	origLogger := zlog.Logger
	zlog.Logger = zerolog.New(&logBuf)
	defer func() { zlog.Logger = origLogger }()

	// An email-like marker used as the alg value itself, guaranteed not to
	// appear anywhere else in the error text.
	const algMarker = "attacker@leaked-alg.example.com"
	token := rawCompactJWTWithAlg(t, algMarker, baseClaims("https://issuer.example.com", "api-1", now))

	_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
		ExpectedAudiences: []string{"api-1"},
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInvalidToken), "expected ErrInvalidToken, got %v", err)
	require.False(t, errors.Is(err, ErrTransient), "an unsupported alg is a parse-time rejection, not a transient JWKS/kid failure")
	require.NotContains(t, err.Error(), algMarker, "ValidateStrictJWT must not leak the attacker-controlled alg header value in its own returned error")

	logged := logBuf.String()
	require.NotContains(t, logged, algMarker, "ValidateStrictJWT must not log the attacker-controlled alg header value")
	require.NotContains(t, logged, token, "ValidateStrictJWT must not log the raw compact JWT")
}

// TestValidateStrictJWT_MalformedKidTypeDoesNotLeakKid proves the structural
// fix (jwtHeaderParseError in oauth/jwt.go) covers the whole class of
// pre-signature header-parse errors, not just the unexpected-alg shape
// above. When the JWT header's `kid` field is present but has the wrong JSON
// type (a JSON object here, instead of a string), go-jose's
// rawHeader.sanitized() fails to unmarshal it and interpolates the raw,
// unverified kid JSON verbatim into its error text via %#v (case
// headerKeyID in go-jose's shared.go). That error surfaces through
// parseAndFetchKeys' "failed to parse signed JWT: %w" wrap before any JWKS
// fetch happens, so it must be caught by the same errors.As-based
// jwtHeaderParseError classification ValidateStrictJWT uses for the
// unexpected-alg case — not by a fourth bespoke, shape-specific check.
// Sabotage case: narrow ValidateStrictJWT's check back down to only
// *jose.ErrUnexpectedSignatureAlgorithm (i.e. revert to enumerating error
// shapes one at a time) and this test fails. Also captures logged output
// (same buffer-swap pattern as TestValidateStrictJWT_NoTokenLeakage — not
// run in parallel with other tests for the same reason: it swaps the shared
// global zerolog logger) and asserts neither the marker nor the raw token
// is logged.
func TestValidateStrictJWT_MalformedKidTypeDoesNotLeakKid(t *testing.T) {
	idp := newStrictTestIdP(t)
	now := time.Now()

	var logBuf bytes.Buffer
	origLogger := zlog.Logger
	zlog.Logger = zerolog.New(&logBuf)
	defer func() { zlog.Logger = origLogger }()

	// An email-like marker nested inside an object-typed kid header,
	// guaranteed not to appear anywhere else in the error text.
	const kidMarker = "attacker@leaked-kid-type.example.com"
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": map[string]interface{}{"leaked-marker": kidMarker},
	}
	token := rawCompactJWTWithHeader(t, header, baseClaims("https://issuer.example.com", "api-1", now))

	_, err := idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
		ExpectedAudiences: []string{"api-1"},
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInvalidToken), "expected ErrInvalidToken, got %v", err)
	require.False(t, errors.Is(err, ErrTransient), "a malformed kid type is a parse-time rejection, not a transient JWKS/kid-rotation failure")
	require.NotContains(t, err.Error(), kidMarker, "ValidateStrictJWT must not leak the attacker-controlled kid header value in its own returned error")

	logged := logBuf.String()
	require.NotContains(t, logged, kidMarker, "ValidateStrictJWT must not log the attacker-controlled kid header value")
	require.NotContains(t, logged, token, "ValidateStrictJWT must not log the raw compact JWT")
}

// TestValidateStrictJWT_ExistingCallersUnaffected is a targeted regression
// check that parseAndVerifyExternalJWT's trailing-slash-tolerant issuer/
// audience matching survived the parseAndFetchKeys extraction unchanged —
// the full pre-existing suite (verifier_test.go) covers this more broadly,
// but this pins the specific slash-tolerance behavior the strict path is
// deliberately NOT allowed to share.
func TestValidateStrictJWT_ExistingCallersUnaffected(t *testing.T) {
	t.Parallel()
	idp := newStrictTestIdP(t)
	idp.verifier = NewVerifier(OAuthConfig{
		JWKSURL: idp.server.URL + "/jwks",
		Issuer:  "https://issuer.example.com", // no trailing slash
	})
	now := time.Now()
	// Token issuer HAS a trailing slash — parseAndVerifyExternalJWT
	// normalizes both sides and must still accept this.
	token := idp.sign(baseClaims("https://issuer.example.com/", "api-1", now))

	claims, err := idp.verifier.parseAndVerifyExternalJWT(context.Background(), token, "api-1")
	require.NoError(t, err)
	require.Equal(t, "user-1", claims.Subject)

	// Same slash-only difference, through the strict path, must fail.
	_, err = idp.verifier.ValidateStrictJWT(context.Background(), token, StrictJWTPolicy{
		ExpectedIssuer:    "https://issuer.example.com",
		ExpectedAudiences: []string{"api-1"},
	})
	require.Error(t, err)
}
