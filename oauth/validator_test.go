package oauth

import (
	"context"
	"errors"
	"testing"

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
