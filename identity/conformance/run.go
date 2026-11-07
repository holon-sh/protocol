// Package conformance tests a live issuer and adapter against the rules of package profile. A backend's own
// tests call Run. Rules a browser must drive run only when Config.SignIn is set and are skipped by name
// otherwise.
package conformance

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/holon-sh/protocol/identity"
	"github.com/holon-sh/protocol/identity/internal/adapter"
	"github.com/holon-sh/protocol/identity/introspection"
	"github.com/holon-sh/protocol/identity/invitation"
	"github.com/holon-sh/protocol/identity/scim"
	"github.com/holon-sh/protocol/identity/tokenclient"
)

const requestTimeout = 30 * time.Second

// Config names the backend under test. The service account is a confidential client allowed the client
// credentials grant of [RFC 6749 §4.4]. HTTP must trust the issuer and the adapter. Resource must already be
// registered, with at least one binding so that a permission-set group exists. BrowserRedirectURI must be on the
// base origin, and the browser client must have {origin}/?signedOut=1 registered as a post-logout redirect URI for
// that origin and for the admin and dev origins protocol.PlaneOrigin derives from it.
//
// [RFC 6749 §4.4]: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
type Config struct {
	Issuer                     string
	Adapter                    string
	Bearer                     string
	BrowserClientID            string
	BrowserClientSecret        string
	CLIClientID                string
	ServiceAccountClientID     string
	ServiceAccountClientSecret string
	Resource                   Resource
	HTTP                       *http.Client
	BrowserRedirectURI         string
	SignIn                     SignIn
}

// Resource is a resource the backend has registered: Audience is its [RFC 8707 §2] resource indicator and
// Scopes the [RFC 6749 §3.3] scope tokens it accepts.
//
// [RFC 8707 §2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
// [RFC 6749 §3.3]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
type Resource struct {
	Audience string
	Scopes   []string
}

// SignIn drives a browser through one sign-in. It answers the URL the issuer redirected to, without following
// it, or an error when the issuer refused the sign-in. The device grant redirects nowhere, so its answer is
// ignored.
type SignIn func(context.Context, SignInRequest) (*url.URL, error)

// SignInRequest is one sign-in. AuthorizationURL is the page to open: an [RFC 6749 §4.1.1] request or an
// [RFC 8628 §3.3] verification URI. When Invitation is set there is no AuthorizationURL, and the hook opens the
// link in the latest message sent to UserName instead. An empty UserName means the caller's own test person,
// who holds Resource.Scopes through a permission set. Otherwise UserName and Password identify a person the
// suite created. UserCode, NewPassword and Name are what to submit if the issuer asks for them. When SameBrowser is
// set the hook opens AuthorizationURL in the browser of the previous sign-in, which is still signed in.
//
// [RFC 6749 §4.1.1]: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1
// [RFC 8628 §3.3]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3.3
type SignInRequest struct {
	AuthorizationURL string
	UserCode         string
	Invitation       bool
	UserName         string
	Password         string
	NewPassword      string
	Name             *scim.Name
	SameBrowser      bool
}

type rule struct {
	name    string
	browser bool
	check   func(*suite, context.Context) error
}

var rules = []rule{
	{name: "discovery serves the required endpoints", check: (*suite).checkDiscovery},
	{name: "client credentials token carries the resource and only registered scopes", check: (*suite).checkClientCredentials},
	{name: "introspection answers RFC 7662 fields to the bearer", check: (*suite).checkIntrospection},
	{name: "token for no resource or an unregistered audience is inactive", check: (*suite).checkUnregisteredAudience},
	{name: "SCIM list", check: (*suite).checkSCIMList},
	{name: "SCIM list answers each person's groups", check: (*suite).checkSCIMListGroups},
	{name: "SCIM filter", check: (*suite).checkSCIMFilter},
	{name: "SCIM create with password", check: (*suite).checkSCIMCreate},
	{name: "SCIM create group", check: (*suite).checkSCIMCreateGroup},
	{name: "SCIM patch", check: (*suite).checkSCIMPatch},
	{name: "SCIM delete", check: (*suite).checkSCIMDelete},
	{name: "invitation returns a result", check: (*suite).checkInvitation},
	{name: "browser client uses the authorization code grant with PKCE S256", browser: true, check: (*suite).checkBrowserClient},
	{name: "cli client is public, uses the device authorization grant with offline_access and revokes its refresh token", browser: true, check: (*suite).checkCLIClient},
	{name: "browser and cli refreshes keep the resource, and one naming another resource is invalid_target", browser: true, check: (*suite).checkRefreshResource},
	{name: "scope is what the subject holds on the resource, in the scope parameter when issued and current at introspection", browser: true, check: (*suite).checkIssuedScope},
	{name: "sign-out with id_token_hint ends the session and redirects to the signed-out page", browser: true, check: (*suite).checkSignOut},
	{name: "personal token has the person's sub, its own client_id and 30 days, and survives browser sign-out", browser: true, check: (*suite).checkPersonalToken},
	{name: "SCIM id is the sub at the browser client, and GET /Users/{sub} lists the person's groups", browser: true, check: (*suite).checkSCIMIDIsSubject},
	{name: "temporary password is replaced at the first sign-in", browser: true, check: (*suite).checkTemporaryPassword},
	{name: "invitation link expires and is refused after setup", browser: true, check: (*suite).checkInvitationLink},
}

// Run runs every rule of package profile that cfg can drive as a subtest of t.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	s, err := newSuite(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runRules(t, s)
}

func runRules(t *testing.T, s *suite) {
	t.Helper()
	for _, r := range rules {
		t.Run(r.name, func(t *testing.T) {
			if r.browser && s.cfg.SignIn == nil {
				t.Skipf("%s: Config.SignIn is not set", r.name)
			}
			err := r.check(s, t.Context())
			var reason skipReason
			if errors.As(err, &reason) {
				t.Skipf("%s: %s", r.name, reason)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func wait(ctx context.Context, duration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(duration):
		return nil
	}
}

type skipReason string

func (r skipReason) Error() string { return string(r) }

type suite struct {
	wait          func(context.Context, time.Duration) error
	cfg           Config
	http          *http.Client
	adapter       *adapter.Client
	users         *scim.Client
	invitations   *invitation.Client
	registrations *identity.Client
	introspector  *introspection.Client
	tokens        *tokenclient.Client
}

func newSuite(cfg Config) (*suite, error) {
	if cfg.HTTP == nil || cfg.Issuer == "" || cfg.BrowserClientID == "" || cfg.BrowserClientSecret == "" || cfg.CLIClientID == "" ||
		cfg.ServiceAccountClientID == "" || cfg.ServiceAccountClientSecret == "" || cfg.Resource.Audience == "" || len(cfg.Resource.Scopes) == 0 {
		return nil, errors.New("conformance needs HTTP, Issuer, all three clients and a Resource with scopes")
	}
	if cfg.SignIn != nil && cfg.BrowserRedirectURI == "" {
		return nil, errors.New("conformance needs BrowserRedirectURI with SignIn")
	}
	raw, rawErr := adapter.NewClient(cfg.Adapter, cfg.Bearer, cfg.HTTP, requestTimeout)
	users, usersErr := scim.NewClient(cfg.Adapter, cfg.Bearer, cfg.HTTP)
	invitations, invitationsErr := invitation.NewClient(cfg.Adapter, cfg.Bearer, cfg.HTTP)
	registrations, registrationsErr := identity.NewClient(cfg.Adapter, cfg.Bearer, cfg.HTTP)
	introspector, introspectorErr := introspection.NewClient(cfg.Adapter, cfg.Bearer, cfg.HTTP)
	tokens, tokensErr := tokenclient.NewClient(cfg.Adapter, cfg.Bearer, cfg.HTTP)
	if err := errors.Join(rawErr, usersErr, invitationsErr, registrationsErr, introspectorErr, tokensErr); err != nil {
		return nil, err
	}
	return &suite{
		wait: wait, cfg: cfg, http: adapter.NoRedirects(cfg.HTTP, requestTimeout), adapter: raw,
		users: users, invitations: invitations, registrations: registrations, introspector: introspector, tokens: tokens,
	}, nil
}
