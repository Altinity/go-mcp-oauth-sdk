package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/rs/zerolog/log"
)

// fetchAuthServerMeta returns the cached or freshly-discovered authorization
// server metadata for issuer. Uses auth.GetAuthServerMetadata which tries the
// MCP-spec-required well-known endpoints in order (OAuth 2.0 first, then OIDC
// discovery, plus path-aware variants).
func (v *Verifier) fetchAuthServerMeta(ctx context.Context, issuer string) (*oauthex.AuthServerMeta, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	v.asMetaMu.RLock()
	if v.asMetaCacheURL == issuer && v.asMetaExpiresAt.After(time.Now()) && v.asMetaCache.Issuer != "" {
		cached := v.asMetaCache
		v.asMetaMu.RUnlock()
		return &cached, nil
	}
	v.asMetaMu.RUnlock()

	httpClient := &http.Client{Timeout: httpTimeout}
	asMeta, err := auth.GetAuthServerMetadata(ctx, issuer, httpClient)
	if err != nil {
		// Discovery failures are network-y by nature (timeouts, DNS,
		// upstream 5xx); mark transient so the sidecar's negative cache
		// doesn't pin a legit token as bad across a blip.
		return nil, fmt.Errorf("failed to discover authorization server metadata for issuer %q: %w: %w", issuer, ErrTransient, err)
	}
	if asMeta == nil {
		return nil, fmt.Errorf("no authorization server metadata found for issuer %q", issuer)
	}

	v.asMetaMu.Lock()
	v.asMetaCache = *asMeta
	v.asMetaCacheURL = issuer
	v.asMetaExpiresAt = jitteredExpiry(time.Now(), v.jwksCacheTTL())
	v.asMetaMu.Unlock()
	return asMeta, nil
}

// FetchAuthServerMeta exposes the cached/discovered auth-server metadata for
// the given issuer. Used by the broker to resolve upstream /authorize and
// /token endpoints when the operator hasn't pinned them explicitly.
func (v *Verifier) FetchAuthServerMeta(ctx context.Context, issuer string) (*oauthex.AuthServerMeta, error) {
	return v.fetchAuthServerMeta(ctx, issuer)
}

// ResolveUserInfoEndpoint returns the OIDC userinfo_endpoint advertised by
// issuer's /.well-known/openid-configuration document. oauthex.AuthServerMeta
// (RFC 8414) doesn't expose this field — userinfo is OIDC-only — so this is
// the surgical fallback when the operator hasn't pinned UserInfoURL.
//
// Returns "" without error when the document doesn't advertise the field; the
// caller treats that the same as "no userinfo configured".
func (v *Verifier) ResolveUserInfoEndpoint(ctx context.Context, issuer string) (string, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return "", fmt.Errorf("issuer is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(closeErr).Msgf("can't close openid-configuration response body for %s", issuer)
		}
	}()
	if resp.StatusCode >= 300 {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var partial struct {
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(body, &partial); err != nil {
		return "", err
	}
	return strings.TrimSpace(partial.UserInfoEndpoint), nil
}
