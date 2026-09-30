package oauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveEmailIdentity(t *testing.T) {
	t.Parallel()
	const ns = "https://example.com/"
	const other = "https://other.example/"
	tests := []struct {
		name     string
		claims   *Claims
		email    string
		verified bool
		err      error
	}{
		{name: "nil claims", err: ErrInvalidToken},
		{name: "no email", claims: &Claims{}, err: ErrEmailClaimMissing},
		{name: "verification alone is not email", claims: &Claims{EmailVerified: true}, err: ErrEmailClaimMissing},
		{name: "standard verified", claims: &Claims{Email: " user@example.com ", EmailVerified: true}, email: "user@example.com", verified: true},
		{name: "standard unverified", claims: &Claims{Email: "user@example.com"}, email: "user@example.com"},
		{name: "standard wins over namespaced identity and evidence", claims: &Claims{
			Email: "standard@example.com",
			Extra: map[string]interface{}{ns + "email": "other@example.com", ns + "email_verified": true},
		}, email: "standard@example.com"},
		{name: "standard wins over ambiguous fallback", claims: &Claims{
			Email: "standard@example.com", EmailVerified: true,
			Extra: map[string]interface{}{ns + "email": "one@example.com", other + "email": "two@example.com"},
		}, email: "standard@example.com", verified: true},
		{name: "namespaced missing evidence", claims: &Claims{Extra: map[string]interface{}{ns + "email": "user@example.com"}}, email: "user@example.com"},
		{name: "namespaced false evidence", claims: &Claims{Extra: map[string]interface{}{ns + "email": "user@example.com", ns + "email_verified": false}}, email: "user@example.com"},
		{name: "namespaced true evidence", claims: &Claims{Extra: map[string]interface{}{ns + "email": " user@example.com ", ns + "email_verified": true}}, email: "user@example.com", verified: true},
		{name: "blank standard falls back without borrowing evidence", claims: &Claims{
			Email: " \t\n", EmailVerified: true, Extra: map[string]interface{}{ns + "email": "user@example.com"},
		}, email: "user@example.com"},
		{name: "standard true cannot verify namespaced email", claims: &Claims{
			EmailVerified: true, Extra: map[string]interface{}{ns + "email": "user@example.com", ns + "email_verified": false},
		}, email: "user@example.com"},
		{name: "other namespace cannot verify email", claims: &Claims{
			Extra: map[string]interface{}{ns + "email": "user@example.com", other + "email_verified": true},
		}, email: "user@example.com"},
		{name: "standard extra evidence cannot verify email", claims: &Claims{
			Extra: map[string]interface{}{ns + "email": "user@example.com", "email_verified": true},
		}, email: "user@example.com"},
		{name: "two different emails ambiguous", claims: &Claims{
			Extra: map[string]interface{}{ns + "email": "one@example.com", other + "email": "two@example.com", ns + "email_verified": true},
		}, err: ErrEmailClaimAmbiguous},
		{name: "identical emails with different provenance ambiguous", claims: &Claims{
			Extra: map[string]interface{}{ns + "email": "user@example.com", other + "email": "user@example.com", ns + "email_verified": true, other + "email_verified": false},
		}, err: ErrEmailClaimAmbiguous},
		{name: "identical verified emails ambiguous", claims: &Claims{
			Extra: map[string]interface{}{ns + "email": "user@example.com", other + "email": "user@example.com", ns + "email_verified": true, other + "email_verified": true},
		}, err: ErrEmailClaimAmbiguous},
		{name: "only exact email suffix considered", claims: &Claims{
			Extra: map[string]interface{}{ns + "Email": "user@example.com", ns + "email/": "user@example.com", "email": "user@example.com", "preferred_email": "user@example.com"},
		}, err: ErrEmailClaimMissing},
		{name: "ignore unusable competing claims", claims: &Claims{
			Extra: map[string]interface{}{ns + "email": "user@example.com", ns + "email_verified": true, other + "email": " \t", "https://number.example/email": 42},
		}, email: "user@example.com", verified: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ResolveEmailIdentity(tt.claims)
			require.ErrorIs(t, err, tt.err)
			require.Equal(t, tt.email, identity.Email)
			require.Equal(t, tt.verified, identity.EmailVerified)
		})
	}
}

func TestResolveEmailIdentityRejectsNonbooleanNamespacedEvidence(t *testing.T) {
	t.Parallel()
	for _, value := range []interface{}{nil, "true", "TRUE", "false", 1, 1.0, []interface{}{true}, map[string]interface{}{"verified": true}} {
		claims := &Claims{Extra: map[string]interface{}{"https://example.com/email": "user@example.com", "https://example.com/email_verified": value}}
		identity, err := ResolveEmailIdentity(claims)
		require.NoError(t, err)
		require.Equal(t, "user@example.com", identity.Email)
		require.False(t, identity.EmailVerified, "nonboolean evidence %T must not verify an email", value)
	}
}

func TestResolveEmailIdentityRejectsUnusableEmails(t *testing.T) {
	t.Parallel()
	for _, value := range []interface{}{nil, "", " \t\n", true, 42, []interface{}{"user@example.com"}, map[string]interface{}{"email": "user@example.com"}} {
		claims := &Claims{Extra: map[string]interface{}{"https://example.com/email": value, "https://example.com/email_verified": true}}
		identity, err := ResolveEmailIdentity(claims)
		require.ErrorIs(t, err, ErrEmailClaimMissing)
		require.Empty(t, identity)
	}
}

func TestResolveEmailIdentityPolicyCompositionPreservesClaims(t *testing.T) {
	t.Parallel()
	original := &Claims{
		Subject: "user-id", Email: " \t", EmailVerified: true, HostedDomain: "example.com",
		Extra: map[string]interface{}{"https://example.com/email": " user@example.com ", "https://example.com/email_verified": false},
	}
	identity, err := ResolveEmailIdentity(original)
	require.NoError(t, err)
	projected := *original
	projected.Email, projected.EmailVerified = identity.Email, identity.EmailVerified
	require.ErrorIs(t, ValidateIdentityClaims(&projected, IdentityPolicy{RequireEmailVerified: true}), ErrEmailNotVerified)
	require.NoError(t, ValidateIdentityClaims(&projected, IdentityPolicy{AllowedEmailDomains: []string{"example.com"}, AllowedHostedDomains: []string{"example.com"}}))
	require.ErrorIs(t, ValidateIdentityClaims(&projected, IdentityPolicy{AllowedEmailDomains: []string{"other.example"}}), ErrUnauthorizedDomain)
	require.Equal(t, " \t", original.Email)
	require.True(t, original.EmailVerified)
	require.Equal(t, map[string]interface{}{"https://example.com/email": " user@example.com ", "https://example.com/email_verified": false}, original.Extra)
}

func TestResolveEmailIdentityErrorsRedactClaimData(t *testing.T) {
	t.Parallel()
	const secret = "secret-claim-marker"
	cases := []*Claims{
		{Extra: map[string]interface{}{secret + "/email": []string{secret}}},
		{Extra: map[string]interface{}{secret + "/email": secret, "other/email": "another-" + secret}},
	}
	for _, claims := range cases {
		identity, err := ResolveEmailIdentity(claims)
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret)
		require.Empty(t, identity)
	}
}
