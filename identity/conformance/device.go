package conformance

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	deviceGrantType    = "urn:ietf:params:oauth:grant-type:device_code"
	defaultPollSeconds = 5
	slowDownIncrement  = 5 * time.Second
)

// deviceAuthorization is the response of [RFC 8628 §3.2].
//
// [RFC 8628 §3.2]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3.2
type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

func (d deviceAuthorization) validate() error {
	switch {
	case d.DeviceCode == "":
		return errors.New("device authorization has no device_code")
	case d.UserCode == "":
		return errors.New("device authorization has no user_code")
	case !httpsEndpoint(d.VerificationURI):
		return fmt.Errorf("verification_uri %q is not an HTTPS URL", d.VerificationURI)
	case d.ExpiresIn <= 0:
		return fmt.Errorf("expires_in %d is not positive", d.ExpiresIn)
	case d.Interval < 0:
		return fmt.Errorf("interval %d is negative", d.Interval)
	}
	return nil
}

// deviceToken drives the device authorization grant of [RFC 8628 §3] as the public cli client, with the resource
// parameter of [RFC 8707 §2] on both the device request and the token poll, and with offline_access, which must
// yield a refresh token.
//
// [RFC 8628 §3]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3
// [RFC 8707 §2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
func (s *suite) deviceToken(ctx context.Context) (token, error) {
	client := oauthClient{id: s.cfg.CLIClientID}
	resource := s.cfg.Resource.Audience
	document, err := s.discover(ctx)
	if err != nil {
		return token{}, err
	}
	var device deviceAuthorization
	request := url.Values{"scope": {"offline_access " + s.resourceScope()}, "resource": {resource}}
	if err := s.post(ctx, document.DeviceAuthorizationEndpoint, client, request, &device); err != nil {
		return token{}, fmt.Errorf("device authorization request: %w", err)
	}
	if err := device.validate(); err != nil {
		return token{}, err
	}
	poll := url.Values{"grant_type": {deviceGrantType}, "device_code": {device.DeviceCode}, "resource": {resource}}
	_, err = s.exchange(ctx, client, poll)
	if err := wantRefused("a poll before sign-in", err, "authorization_pending"); err != nil {
		return token{}, err
	}
	signIn := SignInRequest{AuthorizationURL: cmp.Or(device.VerificationURIComplete, device.VerificationURI), UserCode: device.UserCode}
	if _, err := s.cfg.SignIn(ctx, signIn); err != nil {
		return token{}, fmt.Errorf("sign-in: %w", err)
	}
	issued, err := s.pollDevice(ctx, client, device, poll)
	if err != nil {
		return token{}, fmt.Errorf("device token poll: %w", err)
	}
	if issued.RefreshToken == "" {
		return token{}, errors.New("the device grant with offline_access issued no refresh token")
	}
	return issued, nil
}

// checkCLIClient takes a device grant and expects the person to hold the sub they hold at the browser client, the
// public subject type of [OpenID Connect Core 1.0 §8]. It then refreshes, so that a refusal below can only come
// from revocation, revokes the latest refresh token as [RFC 7009 §2.1] describes and expects the invalid_grant of
// [RFC 6749 §5.2] from using it.
//
// [OpenID Connect Core 1.0 §8]: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
// [RFC 6749 §5.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
// [RFC 7009 §2.1]: https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1
func (s *suite) checkCLIClient(ctx context.Context) error {
	client := oauthClient{id: s.cfg.CLIClientID}
	resource := s.cfg.Resource.Audience
	document, err := s.discover(ctx)
	if err != nil {
		return err
	}
	issued, err := s.deviceToken(ctx)
	if err != nil {
		return err
	}
	cli, err := s.wantActive(ctx, issued.AccessToken, s.cfg.CLIClientID, resource)
	if err != nil {
		return err
	}
	signedIn, err := s.browserToken(ctx, s.resourceScope())
	if err != nil {
		return err
	}
	browser, err := s.wantActive(ctx, signedIn.AccessToken, s.cfg.BrowserClientID, resource)
	if err != nil {
		return err
	}
	if browser.Subject != cli.Subject {
		return fmt.Errorf("one person has sub %q at the cli client and %q at the browser client", cli.Subject, browser.Subject)
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "resource": {resource}}
	refreshed, err := s.exchange(ctx, client, refresh)
	if err != nil {
		return fmt.Errorf("refresh before revocation: %w", err)
	}
	latest := cmp.Or(refreshed.RefreshToken, issued.RefreshToken)
	revocation := url.Values{"token": {latest}, "token_type_hint": {"refresh_token"}}
	if err := s.post(ctx, document.RevocationEndpoint, client, revocation, nil); err != nil {
		return fmt.Errorf("revocation request: %w", err)
	}
	refresh.Set("refresh_token", latest)
	_, err = s.exchange(ctx, client, refresh)
	return wantRefused("a revoked refresh token", err, "invalid_grant")
}

// pollDevice repeats the request of [RFC 8628 §3.4], at the interval of [RFC 8628 §3.2] and backing off as
// [RFC 8628 §3.5] requires.
//
// [RFC 8628 §3.2]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3.2
// [RFC 8628 §3.4]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3.4
// [RFC 8628 §3.5]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5
func (s *suite) pollDevice(ctx context.Context, client oauthClient, device deviceAuthorization, poll url.Values) (token, error) {
	interval := time.Duration(cmp.Or(device.Interval, defaultPollSeconds)) * time.Second
	for remaining := time.Duration(device.ExpiresIn) * time.Second; remaining > 0; remaining -= interval {
		if err := s.wait(ctx, interval); err != nil {
			return token{}, err
		}
		issued, err := s.exchange(ctx, client, poll)
		var refused *rejection
		switch {
		case err == nil:
			return issued, nil
		case !errors.As(err, &refused):
			return token{}, err
		case refused.Code == "slow_down":
			interval += slowDownIncrement
		case refused.Code != "authorization_pending":
			return token{}, err
		}
	}
	return token{}, errors.New("the device code expired while polling")
}
