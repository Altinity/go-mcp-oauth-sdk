package oauth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateIdentityClaims_RequireEmailVerified(t *testing.T) {
	t.Parallel()

	t.Run("present unverified email fails", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{Email: "user@example.com", EmailVerified: false}, IdentityPolicy{
			RequireEmailVerified: true,
		})
		require.ErrorIs(t, err, ErrEmailNotVerified)
	})

	t.Run("present verified email succeeds", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{Email: "user@example.com", EmailVerified: true}, IdentityPolicy{
			RequireEmailVerified: true,
		})
		require.NoError(t, err)
	})

	// Per the plan: a token with no email claim at all is NOT rejected by
	// this check — that's a separate concern owned by username-claim
	// binding. Sabotage case: change the guard to unconditionally require
	// EmailVerified regardless of whether Email is set — this test would
	// then start failing.
	t.Run("no email claim at all does not fail this check", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{Email: "", EmailVerified: false}, IdentityPolicy{
			RequireEmailVerified: true,
		})
		require.NoError(t, err)
	})
}

func TestValidateIdentityClaims_AllowedEmailDomains(t *testing.T) {
	t.Parallel()

	t.Run("matching domain succeeds", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{Email: "user@allowed.com"}, IdentityPolicy{
			AllowedEmailDomains: []string{"allowed.com"},
		})
		require.NoError(t, err)
	})

	t.Run("non-matching domain returns ErrUnauthorizedDomain", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{Email: "user@other.com"}, IdentityPolicy{
			AllowedEmailDomains: []string{"allowed.com"},
		})
		require.ErrorIs(t, err, ErrUnauthorizedDomain)
	})

	// Sabotage case: conflate "no email" with "wrong domain" by returning
	// ErrUnauthorizedDomain (or nil) instead of the distinct sentinel —
	// this test regresses under either sabotage.
	t.Run("absent email returns a distinct error, not ErrUnauthorizedDomain", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{Email: ""}, IdentityPolicy{
			AllowedEmailDomains: []string{"allowed.com"},
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrEmailClaimMissing)
		require.False(t, errors.Is(err, ErrUnauthorizedDomain),
			"absent-email must not be reported as ErrUnauthorizedDomain")
	})
}

func TestValidateIdentityClaims_AllowedHostedDomains(t *testing.T) {
	t.Parallel()

	t.Run("matching hd succeeds", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{HostedDomain: "corp.example.com"}, IdentityPolicy{
			AllowedHostedDomains: []string{"corp.example.com"},
		})
		require.NoError(t, err)
	})

	t.Run("non-matching hd returns ErrUnauthorizedDomain", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{HostedDomain: "other.example.com"}, IdentityPolicy{
			AllowedHostedDomains: []string{"corp.example.com"},
		})
		require.ErrorIs(t, err, ErrUnauthorizedDomain)
	})

	t.Run("missing hd returns ErrUnauthorizedDomain", func(t *testing.T) {
		t.Parallel()
		err := ValidateIdentityClaims(&Claims{HostedDomain: ""}, IdentityPolicy{
			AllowedHostedDomains: []string{"corp.example.com"},
		})
		require.ErrorIs(t, err, ErrUnauthorizedDomain)
	})
}

func TestValidateIdentityClaims_CombinedPolicy(t *testing.T) {
	t.Parallel()
	err := ValidateIdentityClaims(&Claims{
		Email:         "user@corp.example.com",
		EmailVerified: true,
		HostedDomain:  "corp.example.com",
	}, IdentityPolicy{
		RequireEmailVerified: true,
		AllowedEmailDomains:  []string{"corp.example.com"},
		AllowedHostedDomains: []string{"corp.example.com"},
	})
	require.NoError(t, err)
}

// TestValidateIdentityClaims_NoValueLeakage is the marker-based test from
// the invariant map: use a distinctive, credential-adjacent email/domain and
// assert it never appears in any returned error string. Sabotage case:
// interpolate the email/domain into an error via fmt.Errorf and this test
// fails.
func TestValidateIdentityClaims_NoValueLeakage(t *testing.T) {
	t.Parallel()
	const secretEmail = "very-secret-marker-user@super-secret-domain.example"
	const secretDomain = "super-secret-domain.example"
	const secretHD = "super-secret-hd-marker.example"

	cases := []struct {
		name   string
		claims *Claims
		policy IdentityPolicy
	}{
		{
			name:   "unverified email",
			claims: &Claims{Email: secretEmail, EmailVerified: false},
			policy: IdentityPolicy{RequireEmailVerified: true},
		},
		{
			name:   "domain mismatch",
			claims: &Claims{Email: secretEmail},
			policy: IdentityPolicy{AllowedEmailDomains: []string{"totally-different.example"}},
		},
		{
			name:   "hosted domain mismatch",
			claims: &Claims{HostedDomain: secretHD},
			policy: IdentityPolicy{AllowedHostedDomains: []string{"totally-different.example"}},
		},
	}

	for _, tc := range cases {
		err := ValidateIdentityClaims(tc.claims, tc.policy)
		require.Error(t, err, tc.name)
		require.NotContains(t, err.Error(), secretEmail, tc.name)
		require.NotContains(t, err.Error(), secretDomain, tc.name)
		require.NotContains(t, err.Error(), secretHD, tc.name)
	}
}
