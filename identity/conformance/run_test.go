package conformance

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/holon-sh/protocol"
	"github.com/holon-sh/protocol/identity/invitation"
	"github.com/holon-sh/protocol/identity/scim"
)

func newTestSuite(t *testing.T, p *provider) *suite {
	t.Helper()
	s, err := newSuite(p.config())
	if err != nil {
		t.Fatal(err)
	}
	s.wait = p.advance
	return s
}

func TestRunPassesAConformantBackend(t *testing.T) {
	runRules(t, newTestSuite(t, newProvider(t, faults{})))
}

func TestRunSkipsBrowserRulesWithoutTheHook(t *testing.T) {
	cfg := newProvider(t, faults{}).config()
	cfg.SignIn = nil
	Run(t, cfg)
}

func TestEveryRuleIsDetected(t *testing.T) {
	for _, test := range []struct {
		name   string
		check  func(*suite, context.Context) error
		faults faults
		want   string
	}{
		{"issuer differs", (*suite).checkDiscovery, faults{wrongIssuer: true}, "issuer"},
		{"unregistered scope granted", (*suite).checkClientCredentials, faults{leakScope: true}, leakedScope},
		{"no bearer accepted", (*suite).checkIntrospection, faults{openIntrospection: true}, "no bearer"},
		{"unknown token active", (*suite).checkIntrospection, faults{activeUnknownToken: true}, "unknown to the issuer"},
		{"client_id differs", (*suite).checkIntrospection, faults{wrongClientID: true}, "client_id"},
		{"aud differs", (*suite).checkIntrospection, faults{wrongAudience: true}, "aud"},
		{"never-registered audience active", (*suite).checkUnregisteredAudience, faults{mintUnregistered: true, activeAfterDelete: true}, "never registered"},
		{"no resource active", (*suite).checkUnregisteredAudience, faults{noResourceDefaults: true}, "for no resource"},
		{"active after deletion", (*suite).checkUnregisteredAudience, faults{activeAfterDelete: true}, "before its resource was deleted"},
		{"count ignored", (*suite).checkSCIMList, faults{countIgnored: true}, "first page"},
		{"zero count returns resources", (*suite).checkSCIMList, faults{zeroCountReturnsAll: true}, "count 0"},
		{"filter ignored", (*suite).checkSCIMFilter, faults{filterIgnored: true}, "filter"},
		{"no pendingSetup", (*suite).checkSCIMCreate, faults{noPendingSetup: true}, "pendingSetup"},
		{"duplicate userName accepted", (*suite).checkSCIMCreate, faults{duplicateUserName: true}, "one userName"},
		{"group created twice", (*suite).checkSCIMCreateGroup, faults{duplicateGroup: true}, "one externalId succeeded"},
		{"created group unlisted", (*suite).checkSCIMCreateGroup, faults{listDropsCreatedGroups: true}, "does not include"},
		{"patch ignored", (*suite).checkSCIMPatch, faults{patchIgnored: true}, "replace active"},
		{"members ignored", (*suite).checkSCIMPatch, faults{membersIgnored: true}, "membership"},
		{"delete keeps the user", (*suite).checkSCIMDelete, faults{deleteKeeps: true}, "after delete"},
		{"sent disagrees with capabilities", (*suite).checkInvitation, faults{sentWithoutCapability: true}, "capabilities"},
		{"repeat invites a new user", (*suite).checkInvitation, faults{inviteNewUserEachTime: true}, "repeat"},
		{"groups dropped", (*suite).checkInvitation, faults{inviteDropsGroups: true}, "groups"},
		{"list drops groups", (*suite).checkSCIMListGroups, faults{listDropsGroups: true}, "groups"},
		{"any verifier accepted", (*suite).checkBrowserClient, faults{anyVerifier: true}, "code_verifier"},
		{"device token issued before sign-in", (*suite).checkCLIClient, faults{deviceApprovedEarly: true}, "before sign-in"},
		{"no refresh token with offline_access", (*suite).checkCLIClient, faults{deviceNoRefresh: true}, "no refresh token"},
		{"one person has two subjects", (*suite).checkCLIClient, faults{pairwiseSubject: true}, "at the browser client"},
		{"refresh answers invalid_grant", (*suite).checkRefreshResource, faults{refreshInvalidGrant: true}, "invalid_grant"},
		{"second cli refresh loses the audience", (*suite).checkRefreshResource, faults{cliRefreshLosesAudience: true}, "cli client: access token of refresh 2"},
		{"cli refresh serves another resource", (*suite).checkRefreshResource, faults{cliRefreshAnyResource: true}, "cli client: refresh for another resource succeeded"},
		{"revoked refresh token still refreshes", (*suite).checkCLIClient, faults{revocationIgnored: true}, "a revoked refresh token"},
		{"no refresh token ever refreshes", (*suite).checkCLIClient, faults{refreshRefused: true}, "refresh before revocation"},
		{"unregistered scope issued", (*suite).checkIssuedScope, faults{leakScope: true}, leakedScope},
		{"held scope issued only when named", (*suite).checkIssuedScope, faults{scopeOnlyWhenNamed: true}, "held but not issued"},
		{"scope fixed at issue", (*suite).checkIssuedScope, faults{scopeFixedAtIssue: true}, "no longer held"},
		{"scope never grows past what was issued", (*suite).checkIssuedScope, faults{scopeNeverGrows: true}, "gained permission sets: scope"},
		{"token inactive once its subject holds nothing", (*suite).checkIssuedScope, faults{inactiveWithoutScope: true}, "lost its permission sets"},
		{"personal token names another client", (*suite).checkPersonalToken, faults{wrongClientID: true}, "personal token: client_id"},
		{"personal token has another subject", (*suite).checkPersonalToken, faults{pairwiseSubject: true}, "at the browser client"},
		{"personal token shorter than 30 days", (*suite).checkPersonalToken, faults{personalTokenShort: true}, "want 30 days"},
		{"personal token asks a signed-in person again", (*suite).checkPersonalToken, faults{personalTokenAsksAgain: true}, "login_required"},
		{"sign-out ended no session", (*suite).checkPersonalToken, faults{signOutKeepsAccess: true}, "of a signed-out session"},
		{"sign-out kills tokens from earlier seconds", (*suite).checkPersonalToken, faults{signOutRaisesNotBefore: true}, "personal token after sign-out"},
		{"sign-out keeps the access token", (*suite).checkSignOut, faults{signOutKeepsAccess: true}, "of a signed-out session"},
		{"sign-out keeps the refresh token", (*suite).checkSignOut, faults{signOutKeepsRefresh: true}, "refresh after sign-out"},
		{"signed-out page unregistered on the base origin", (*suite).checkSignOut, faults{signedOutUnregistered: protocol.BasePlane}, "base origin: sign-out answered"},
		{"signed-out page unregistered on the admin origin", (*suite).checkSignOut, faults{signedOutUnregistered: protocol.AdminPlane}, "admin origin: sign-out answered"},
		{"signed-out page unregistered on the dev origin", (*suite).checkSignOut, faults{signedOutUnregistered: protocol.DevPlane}, "dev origin: sign-out answered"},
		{"refresh refused before sign-out", (*suite).checkSignOut, faults{refreshRefused: true}, "refresh before sign-out"},
		{"same password accepted", (*suite).checkTemporaryPassword, faults{samePasswordAccepted: true}, "accepted the temporary password"},
		{"name not collected", (*suite).checkTemporaryPassword, faults{nameNotCollected: true}, "name"},
		{"still pending after setup", (*suite).checkTemporaryPassword, faults{stillPending: true}, "pendingSetup"},
		{"link reusable", (*suite).checkInvitationLink, faults{linkReusable: true}, "after the person finished"},
		{"link never expires", (*suite).checkInvitationLink, faults{linkNeverExpires: true}, "after its lifetime"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.check(newTestSuite(t, newProvider(t, test.faults)), t.Context())
			if err == nil {
				t.Fatal("the rule passed")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("the rule failed for another reason: %v", err)
			}
		})
	}
}

func TestConformantVariants(t *testing.T) {
	t.Run("an issuer may mint an inactive token for an unregistered audience", func(t *testing.T) {
		s := newTestSuite(t, newProvider(t, faults{mintUnregistered: true}))
		if err := s.checkUnregisteredAudience(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a backend without mail passes the invitation rule and skips the link", func(t *testing.T) {
		s := newTestSuite(t, newProvider(t, faults{noMail: true}))
		if err := s.checkInvitation(t.Context()); err != nil {
			t.Fatal(err)
		}
		var reason skipReason
		if err := s.checkInvitationLink(t.Context()); !errors.As(err, &reason) {
			t.Fatalf("link rule: %v", err)
		}
	})
}

func TestDeviceGrantVariants(t *testing.T) {
	for _, test := range []struct {
		name      string
		faults    faults
		slowDowns int
	}{
		{name: "an issuer without a complete verification URI", faults: faults{noCompleteVerificationURI: true}},
		{name: "an issuer that asks for slower polling", faults: faults{slowDownOnce: true}, slowDowns: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newProvider(t, test.faults)
			if err := newTestSuite(t, p).checkCLIClient(t.Context()); err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.slowDowns != test.slowDowns {
				t.Fatalf("slow_down answered %d times, want %d", p.slowDowns, test.slowDowns)
			}
		})
	}
}

func TestDeviceAuthorizationValidate(t *testing.T) {
	valid := deviceAuthorization{DeviceCode: "d", UserCode: "u", VerificationURI: "https://issuer.example/verify", ExpiresIn: 600}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*deviceAuthorization){
		"no device code":    func(d *deviceAuthorization) { d.DeviceCode = "" },
		"no user code":      func(d *deviceAuthorization) { d.UserCode = "" },
		"plain HTTP":        func(d *deviceAuthorization) { d.VerificationURI = "http://issuer.example/verify" },
		"no expiry":         func(d *deviceAuthorization) { d.ExpiresIn = 0 },
		"negative interval": func(d *deviceAuthorization) { d.Interval = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			device := valid
			change(&device)
			if err := device.validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestNewSuiteRejects(t *testing.T) {
	valid := Config{
		Issuer: "https://issuer.example", Adapter: "https://adapter.example", Bearer: "bearer",
		BrowserClientID: "browser", BrowserClientSecret: "secret", CLIClientID: "cli",
		ServiceAccountClientID: "service", ServiceAccountClientSecret: "secret",
		Resource: Resource{Audience: "https://resource.example", Scopes: []string{"read"}}, HTTP: http.DefaultClient,
	}
	if _, err := newSuite(valid); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"no service account": func(c *Config) { c.ServiceAccountClientID = "" },
		"plain HTTP adapter": func(c *Config) { c.Adapter = "http://adapter.example" },
		"hook without redirect": func(c *Config) {
			c.SignIn = func(context.Context, SignInRequest) (*url.URL, error) { return nil, nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			change(&cfg)
			if _, err := newSuite(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPKCEChallengeMatchesTheRFCVector(t *testing.T) {
	if got := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %q", got)
	}
}

func TestDiscoveryValidate(t *testing.T) {
	valid := discovery{
		Issuer: "https://issuer.example", AuthorizationEndpoint: "https://issuer.example/a", DeviceAuthorizationEndpoint: "https://issuer.example/d",
		TokenEndpoint: "https://issuer.example/t", RevocationEndpoint: "https://issuer.example/r", EndSessionEndpoint: "https://issuer.example/e", JWKSURI: "https://issuer.example/k",
		CodeChallengeMethods: []string{"plain", "S256"},
	}
	if err := valid.validate("https://issuer.example"); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*discovery){
		"no authorization":       func(d *discovery) { d.AuthorizationEndpoint = "" },
		"no device":              func(d *discovery) { d.DeviceAuthorizationEndpoint = "" },
		"no revocation":          func(d *discovery) { d.RevocationEndpoint = "" },
		"no end session":         func(d *discovery) { d.EndSessionEndpoint = "" },
		"no jwks":                func(d *discovery) { d.JWKSURI = "" },
		"plain HTTP token":       func(d *discovery) { d.TokenEndpoint = "http://issuer.example/t" },
		"plain PKCE only":        func(d *discovery) { d.CodeChallengeMethods = []string{"plain"} },
		"no client_secret_basic": func(d *discovery) { d.TokenEndpointAuth = []string{"private_key_jwt"} },
	} {
		t.Run(name, func(t *testing.T) {
			document := valid
			change(&document)
			if err := document.validate("https://issuer.example"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestWantIssuedScope(t *testing.T) {
	for _, scope := range []string{"", "openid app:read"} {
		if err := wantIssuedScope(scope, testScopes); err == nil {
			t.Errorf("wantIssuedScope(%q) accepted", scope)
		}
	}
}

func TestAuthorizationCode(t *testing.T) {
	const redirectURI, state = "https://holon.example/callback", "state"
	for name, raw := range map[string]string{
		"other target": "https://elsewhere.example/callback?code=abc&state=state",
		"wrong state":  "https://holon.example/callback?code=abc&state=other",
		"error":        "https://holon.example/callback?error=access_denied&state=state",
	} {
		t.Run(name, func(t *testing.T) {
			redirect, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if code, err := authorizationCode(redirect, redirectURI, state); err == nil {
				t.Fatalf("accepted code %q", code)
			}
		})
	}
}

func TestValidateResult(t *testing.T) {
	now := time.Unix(1000, 0)
	for name, result := range map[string]invitation.Result{
		"no user":                      {Sent: true, ExpiresAt: now.Add(time.Hour)},
		"not sent with the capability": {UserID: "u"},
		"already expired":              {UserID: "u", Sent: true, ExpiresAt: now},
		"outlives the lifetime":        {UserID: "u", Sent: true, ExpiresAt: now.Add(2 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateResult(result, scim.Capabilities{Invitations: true}, time.Hour, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
