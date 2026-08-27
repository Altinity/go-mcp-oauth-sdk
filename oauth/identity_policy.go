package oauth

import "fmt"

// IdentityPolicy configures identity-level checks applied to already
// signature/claim-validated Claims: verified-email enforcement and
// email/hosted-domain allow-listing. This is a lift-and-share of the
// semantics the ch-jwt-verify sidecar (altinity-oauth-helper) currently
// implements locally, so it is a behavior-preserving move, not a behavior
// change — see ValidateIdentityClaims for the exact rules.
type IdentityPolicy struct {
	// RequireEmailVerified rejects a token whose `email` claim is present
	// but `email_verified` is false. A token with no email claim at all is
	// not rejected by this check — that is a separate concern for whatever
	// username-claim binding decides an email is required at all.
	RequireEmailVerified bool
	// AllowedEmailDomains, when non-empty, requires Claims.Email to be
	// non-empty and its domain (via EmailDomain) to be a member of this
	// list (via ContainsDomain).
	AllowedEmailDomains []string
	// AllowedHostedDomains, when non-empty, requires Claims.HostedDomain
	// (the `hd` claim) to be non-empty and a member of this list.
	AllowedHostedDomains []string
}

// ValidateIdentityClaims applies policy to claims and returns nil when every
// configured check passes.
//
//   - RequireEmailVerified: rejects (ErrEmailNotVerified) only when an
//     `email` claim is actually present and EmailVerified is false. A token
//     with no email claim at all is not rejected by this check.
//   - AllowedEmailDomains (non-empty): requires a non-empty Email, computes
//     its domain via EmailDomain, and requires ContainsDomain(policy.
//     AllowedEmailDomains, domain); returns ErrUnauthorizedDomain on a
//     domain mismatch, or the distinct ErrEmailClaimMissing when
//     Email == "" — the two are never conflated, so callers (and their
//     redaction/logging) can tell "no email to check" apart from "email
//     present but wrong domain" without either error ever containing the
//     email value.
//   - AllowedHostedDomains (non-empty): requires a non-empty HostedDomain
//     (`hd` claim) that is a member of AllowedHostedDomains; returns
//     ErrUnauthorizedDomain on a mismatch or on a missing `hd`.
//
// No returned error contains the email address, domain, or any other
// claim value — every error here is a fixed sentinel with static text.
func ValidateIdentityClaims(claims *Claims, policy IdentityPolicy) error {
	if claims == nil {
		return fmt.Errorf("%w: claims are required", ErrInvalidToken)
	}

	if policy.RequireEmailVerified && claims.Email != "" && !claims.EmailVerified {
		return ErrEmailNotVerified
	}

	if len(policy.AllowedEmailDomains) > 0 {
		if claims.Email == "" {
			return ErrEmailClaimMissing
		}
		domain := EmailDomain(claims.Email)
		if domain == "" || !ContainsDomain(policy.AllowedEmailDomains, domain) {
			return ErrUnauthorizedDomain
		}
	}

	if len(policy.AllowedHostedDomains) > 0 {
		if claims.HostedDomain == "" || !ContainsDomain(policy.AllowedHostedDomains, claims.HostedDomain) {
			return ErrUnauthorizedDomain
		}
	}

	return nil
}
