package conformance

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/holon-sh/protocol"
	"github.com/holon-sh/protocol/identity"
)

func uniqueAudience() string {
	return "https://conformance-" + strings.ToLower(rand.Text()) + ".example.test/"
}

func (s *suite) checkDiscovery(ctx context.Context) error {
	_, err := s.discover(ctx)
	return err
}

func (s *suite) checkClientCredentials(ctx context.Context) error {
	resource := s.cfg.Resource
	issued, err := s.clientCredentials(ctx, resource.Audience, append(slices.Clone(resource.Scopes), unregisteredScope)...)
	if err != nil {
		return err
	}
	if err := onlyRegistered(issued.Scope, resource.Scopes); err != nil {
		return fmt.Errorf("token response: %w", err)
	}
	result, err := s.wantActive(ctx, issued.AccessToken, s.cfg.ServiceAccountClientID, resource.Audience)
	if err != nil {
		return err
	}
	if err := onlyRegistered(result.Scope, resource.Scopes); err != nil {
		return fmt.Errorf("introspection: %w", err)
	}
	return nil
}

func (s *suite) checkIntrospection(ctx context.Context) error {
	issued, err := s.clientCredentials(ctx, s.cfg.Resource.Audience)
	if err != nil {
		return err
	}
	for _, caller := range []struct{ name, credential string }{{"no bearer", ""}, {"a wrong bearer", s.cfg.Bearer + "x"}} {
		_, err := s.introspect(ctx, caller.credential, issued.AccessToken)
		var refused *rejection
		switch {
		case err == nil:
			return fmt.Errorf("introspection with %s succeeded, want status 401", caller.name)
		case !errors.As(err, &refused) || refused.Status != http.StatusUnauthorized || !strings.HasPrefix(refused.Challenge, "Bearer"):
			return fmt.Errorf("introspection with %s: %w, want status 401 with a Bearer challenge", caller.name, err)
		}
	}
	if _, err := s.wantActive(ctx, issued.AccessToken, s.cfg.ServiceAccountClientID, s.cfg.Resource.Audience); err != nil {
		return err
	}
	return s.wantInactive(ctx, rand.Text(), "unknown to the issuer")
}

// wantUnusable requests a token for resource, which no registration holds, and expects the invalid_target code of
// [RFC 8707 §2] or a token nothing accepts.
//
// [RFC 8707 §2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
func (s *suite) wantUnusable(ctx context.Context, resource, description string) error {
	issued, err := s.clientCredentials(ctx, resource)
	if err != nil {
		return wantRefused(description, err, "invalid_target")
	}
	return s.wantInactive(ctx, issued.AccessToken, description)
}

func (s *suite) checkUnregisteredAudience(ctx context.Context) error {
	if err := s.wantUnusable(ctx, uniqueAudience(), "minted for an audience never registered"); err != nil {
		return err
	}
	if err := s.wantUnusable(ctx, "", "minted for no resource"); err != nil {
		return err
	}
	spec := throwawaySpec()
	if err := s.registrations.Ensure(ctx, spec); err != nil {
		return fmt.Errorf("register %s: %w", spec.Audience, err)
	}
	defer func() { _ = s.registrations.Delete(ctx, spec) }()
	issued, err := s.clientCredentials(ctx, spec.Audience)
	if err != nil {
		return err
	}
	if _, err := s.wantActive(ctx, issued.AccessToken, s.cfg.ServiceAccountClientID, spec.Audience); err != nil {
		return err
	}
	if err := s.registrations.Delete(ctx, spec); err != nil {
		return fmt.Errorf("delete %s: %w", spec.Audience, err)
	}
	if err := s.wantInactive(ctx, issued.AccessToken, "minted before its resource was deleted"); err != nil {
		return err
	}
	if err := s.registrations.Ensure(ctx, spec); err != nil {
		return fmt.Errorf("register %s again: %w", spec.Audience, err)
	}
	return s.wantInactive(ctx, issued.AccessToken, "minted before its resource was registered again")
}

func throwawaySpec() identity.Spec {
	return identity.Spec{Kind: "ConformanceResource", UID: strings.ToLower(rand.Text()), Audience: uniqueAudience(), Scopes: []string{"conformance:read"}}
}

func wantRefused(action string, err error, code string) error {
	var refused *rejection
	switch {
	case errors.As(err, &refused) && refused.Code == code:
		return nil
	case err == nil:
		return fmt.Errorf("%s succeeded, want %s", action, code)
	}
	return fmt.Errorf("%s: %w, want %s", action, err, code)
}

func (s *suite) resourceScope() string {
	return strings.Join(s.cfg.Resource.Scopes, " ")
}

func (s *suite) checkBrowserClient(ctx context.Context) error {
	first, err := s.authorize(ctx, s.resourceScope(), SignInRequest{})
	if err != nil {
		return err
	}
	first.verifier = rand.Text() + rand.Text()
	_, err = s.redeem(ctx, first)
	if err := wantRefused("a wrong code_verifier", err, "invalid_grant"); err != nil {
		return err
	}
	issued, err := s.browserToken(ctx, s.resourceScope())
	if err != nil {
		return err
	}
	_, err = s.wantActive(ctx, issued.AccessToken, s.cfg.BrowserClientID, s.cfg.Resource.Audience)
	return err
}

// checkRefreshResource holds the refreshes of the browser client's online grant and the cli client's offline grant
// to the same rules.
func (s *suite) checkRefreshResource(ctx context.Context) error {
	browser, err := s.browserToken(ctx, s.resourceScope())
	if err != nil {
		return err
	}
	if err := s.wantRefreshesKeepResource(ctx, s.browserClient(), browser.RefreshToken); err != nil {
		return fmt.Errorf("browser client: %w", err)
	}
	cli, err := s.deviceToken(ctx)
	if err != nil {
		return err
	}
	if err := s.wantRefreshesKeepResource(ctx, oauthClient{id: s.cfg.CLIClientID}, cli.RefreshToken); err != nil {
		return fmt.Errorf("cli client: %w", err)
	}
	return nil
}

// wantRefreshesKeepResource refreshes twice, because an issuer can lose the resource from the refresh token it
// rotates to and only the next access token shows it, and holds each access token to the audience of
// [RFC 8707 §2.2]. It then expects the invalid_target code of [RFC 8707 §2] from a refresh naming another resource.
// An issuer may count that refusal as a use of the token, so nothing can follow it.
//
// [RFC 8707 §2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
// [RFC 8707 §2.2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2
func (s *suite) wantRefreshesKeepResource(ctx context.Context, client oauthClient, latest string) error {
	if latest == "" {
		return errors.New("no refresh token was issued")
	}
	resource := s.cfg.Resource.Audience
	for attempt := range 2 {
		refreshed, err := s.exchange(ctx, client, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {latest}, "resource": {resource},
		})
		if err != nil {
			return fmt.Errorf("refresh %d for the same resource: %w", attempt+1, err)
		}
		if _, err := s.wantActive(ctx, refreshed.AccessToken, client.id, resource); err != nil {
			return fmt.Errorf("access token of refresh %d: %w", attempt+1, err)
		}
		latest = cmp.Or(refreshed.RefreshToken, latest)
	}
	other := throwawaySpec()
	if err := s.registrations.Ensure(ctx, other); err != nil {
		return fmt.Errorf("register %s: %w", other.Audience, err)
	}
	defer func() { _ = s.registrations.Delete(ctx, other) }()
	_, err := s.exchange(ctx, client, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {latest}, "resource": {other.Audience},
	})
	return wantRefused("refresh for another resource", err, "invalid_target")
}

func (s *suite) checkSignOut(ctx context.Context) error {
	callback, err := url.Parse(s.cfg.BrowserRedirectURI)
	if err != nil {
		return err
	}
	for _, plane := range []protocol.Plane{protocol.BasePlane, protocol.AdminPlane, protocol.DevPlane} {
		origin, err := protocol.PlaneOrigin(callback.Scheme+"://"+callback.Host, plane, "")
		if err != nil {
			return err
		}
		if err := s.wantSignOut(ctx, origin+"/?signedOut=1"); err != nil {
			return fmt.Errorf("%s origin: %w", plane, err)
		}
	}
	return nil
}

// wantSignOut signs in and sends the [OpenID Connect RP-Initiated Logout 1.0 §2] request Holon redirects a browser to,
// with the ID token from sign-in as the hint. A refresh comes first, so that the hint is older than the session's
// latest tokens, as it is when Holon signs out, and so that a refusal below can only come from sign-out. The provider
// must redirect to the signed-out page, [OpenID Connect RP-Initiated Logout 1.0 §3], and the latest tokens must stop
// working.
//
// [OpenID Connect RP-Initiated Logout 1.0 §2]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// [OpenID Connect RP-Initiated Logout 1.0 §3]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
func (s *suite) wantSignOut(ctx context.Context, signedOut string) error {
	issued, err := s.browserToken(ctx, "openid "+s.resourceScope())
	if err != nil {
		return err
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "resource": {s.cfg.Resource.Audience}}
	refreshed, err := s.exchange(ctx, s.browserClient(), refresh)
	if err != nil {
		return fmt.Errorf("refresh before sign-out: %w", err)
	}
	status, location, err := s.endSession(ctx, issued.IDToken, signedOut)
	if err != nil {
		return fmt.Errorf("sign-out request: %w", err)
	}
	if location != signedOut {
		return fmt.Errorf("sign-out answered status %d and location %q, want a redirect to %q", status, location, signedOut)
	}
	if err := s.wantInactive(ctx, refreshed.AccessToken, "of a signed-out session"); err != nil {
		return err
	}
	refresh.Set("refresh_token", cmp.Or(refreshed.RefreshToken, issued.RefreshToken))
	_, err = s.exchange(ctx, s.browserClient(), refresh)
	return wantRefused("refresh after sign-out", err, "invalid_grant")
}

func (s *suite) endSession(ctx context.Context, hint, redirectURI string) (int, string, error) {
	document, err := s.discover(ctx)
	if err != nil {
		return 0, "", err
	}
	query := url.Values{"client_id": {s.cfg.BrowserClientID}, "id_token_hint": {hint}, "post_logout_redirect_uri": {redirectURI}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, document.EndSessionEndpoint+"?"+query.Encode(), nil)
	if err != nil {
		return 0, "", err
	}
	response, err := s.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode, response.Header.Get("Location"), nil
}

func (s *suite) checkIssuedScope(ctx context.Context) error {
	issued, err := s.browserToken(ctx, "openid "+s.resourceScope()+" "+unregisteredScope)
	if err != nil {
		return err
	}
	return wantIssuedScope(issued.Scope, s.cfg.Resource.Scopes)
}

// wantIssuedScope holds the scope response parameter to [RFC 6749 §5.1]: the request named a scope nobody can
// hold, so the issued scope differs and the parameter is required.
//
// [RFC 6749 §5.1]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
func wantIssuedScope(scope string, registered []string) error {
	if scope == "" {
		return errors.New("the issued scope differs from the request but the token response has no scope parameter")
	}
	if err := onlyRegistered(scope, registered); err != nil {
		return err
	}
	granted := strings.Fields(scope)
	for _, want := range append([]string{"openid"}, registered...) {
		if !slices.Contains(granted, want) {
			return fmt.Errorf("scope %q was requested and held but not issued in %q", want, scope)
		}
	}
	return nil
}
