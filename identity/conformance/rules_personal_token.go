package conformance

import (
	"context"
	"fmt"
	"time"

	"github.com/holon-sh/protocol"
	"github.com/holon-sh/protocol/identity/tokenclient"
)

const (
	personalTokenLifetime = 30 * 24 * time.Hour
	lifetimeTolerance     = time.Minute
	pastTheMintSecond     = 2 * time.Second
)

func (s *suite) checkPersonalToken(ctx context.Context) error {
	audience := s.cfg.Resource.Audience
	signedOut, err := s.signedOutPage(protocol.BasePlane)
	if err != nil {
		return err
	}
	credentials, err := s.tokens.Create(ctx, tokenclient.Request{Name: "conformance"})
	if err != nil {
		return fmt.Errorf("create a token client: %w", err)
	}
	browser, err := s.browserToken(ctx)
	if err != nil {
		return err
	}
	signIn, err := s.authorize(ctx, oauthClient{id: credentials.ClientID, secret: credentials.ClientSecret}, SignInRequest{SameBrowser: true})
	if err != nil {
		return fmt.Errorf("personal token: %w", err)
	}
	personal, err := s.redeem(ctx, signIn)
	if err != nil {
		return fmt.Errorf("personal token: %w", err)
	}
	minted, err := s.wantActive(ctx, personal.AccessToken, credentials.ClientID, audience)
	if err != nil {
		return fmt.Errorf("personal token: %w", err)
	}
	signedIn, err := s.wantActive(ctx, browser.AccessToken, s.cfg.BrowserClientID, audience)
	if err != nil {
		return err
	}
	if minted.Subject != signedIn.Subject {
		return fmt.Errorf("one person has sub %q at the token client and %q at the browser client", minted.Subject, signedIn.Subject)
	}
	lifetime := time.Until(time.Unix(minted.Expiry, 0))
	if (lifetime - personalTokenLifetime).Abs() > lifetimeTolerance {
		return fmt.Errorf("personal token exp is %s away, want 30 days", lifetime)
	}
	if err := s.wait(ctx, pastTheMintSecond); err != nil {
		return err
	}
	if err := s.wantSignOut(ctx, browser, signedOut); err != nil {
		return err
	}
	if _, err := s.wantActive(ctx, personal.AccessToken, credentials.ClientID, audience); err != nil {
		return fmt.Errorf("personal token after sign-out: %w", err)
	}
	return nil
}
