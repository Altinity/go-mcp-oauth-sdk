package oauth

import "strings"

// EmailIdentity pairs an email address with the verification evidence from
// its own claim namespace.
type EmailIdentity struct {
	Email         string
	EmailVerified bool
}

// ResolveEmailIdentity resolves an email and its corresponding verification
// evidence from already cryptographically validated claims. It does not verify
// a token or enforce an IdentityPolicy itself.
//
// A nonblank standard Email takes precedence and uses only EmailVerified.
// Otherwise, exactly one nonblank string claim ending in /email must exist in
// Extra. Its verification evidence is the boolean true at that exact claim
// key plus "_verified" (for example, https://example.com/email_verified).
// Standard email_verified and other namespaces cannot verify this email.
// Missing, false, or nonboolean namespaced evidence returns EmailVerified=false.
// Multiple usable namespaced email claims are ambiguous even when their values
// match, since their verification provenance differs.
//
// Returned emails are trimmed. Missing and ambiguous emails return
// ErrEmailClaimMissing and ErrEmailClaimAmbiguous respectively; nil claims
// return ErrInvalidToken. Errors never contain claim names or values, and
// claims is never modified.
//
// Callers authenticating by email should resolve once and apply
// ValidateIdentityClaims to a shallow copy of claims with Email and
// EmailVerified set to these returned values. This binds verified-email and
// domain policy to the same email used for authentication, while retaining
// the original claims for other consumers.
func ResolveEmailIdentity(claims *Claims) (EmailIdentity, error) {
	if claims == nil {
		return EmailIdentity{}, ErrInvalidToken
	}
	if email := strings.TrimSpace(claims.Email); email != "" {
		return EmailIdentity{Email: email, EmailVerified: claims.EmailVerified}, nil
	}

	var emailKey string
	var email string
	for key, value := range claims.Extra {
		if !strings.HasSuffix(key, "/email") {
			continue
		}
		candidate, ok := value.(string)
		if !ok {
			continue
		}
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if emailKey != "" {
			return EmailIdentity{}, ErrEmailClaimAmbiguous
		}
		emailKey, email = key, candidate
	}
	if emailKey == "" {
		return EmailIdentity{}, ErrEmailClaimMissing
	}
	verified, _ := claims.Extra[emailKey+"_verified"].(bool)
	return EmailIdentity{Email: email, EmailVerified: verified}, nil
}
