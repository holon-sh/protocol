package conformance

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/holon-sh/protocol/identity/introspection"
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
		{"unregistered scope granted", (*suite).checkClientCredentials, faults{leakScope: true}, unregisteredScope},
		{"no bearer accepted", (*suite).checkIntrospection, faults{openIntrospection: true}, "no bearer"},
		{"unknown token active", (*suite).checkIntrospection, faults{activeUnknownToken: true}, "unknown to the issuer"},
		{"never-registered audience active", (*suite).checkUnregisteredAudience, faults{mintUnregistered: true, activeAfterDelete: true}, "never registered"},
		{"active after deletion", (*suite).checkUnregisteredAudience, faults{activeAfterDelete: true}, "before its resource was deleted"},
		{"count ignored", (*suite).checkSCIMList, faults{countIgnored: true}, "first page"},
		{"zero count returns resources", (*suite).checkSCIMList, faults{zeroCountReturnsAll: true}, "count 0"},
		{"filter ignored", (*suite).checkSCIMFilter, faults{filterIgnored: true}, "filter"},
		{"no pendingSetup", (*suite).checkSCIMCreate, faults{noPendingSetup: true}, "pendingSetup"},
		{"duplicate userName accepted", (*suite).checkSCIMCreate, faults{duplicateUserName: true}, "one userName"},
		{"group created twice", (*suite).checkSCIMCreateGroup, faults{duplicateGroup: true}, "one externalId succeeded"},
		{"created group unlisted", (*suite).checkSCIMCreateGroup, faults{listDropsCreatedGroups: true}, "does not include"},
		{"created group unlisted and start ignored", (*suite).checkSCIMCreateGroup, faults{listDropsCreatedGroups: true, startIgnored: true}, "does not include"},
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
		{"refresh answers invalid_grant", (*suite).checkRefreshResource, faults{refreshInvalidGrant: true}, "invalid_grant"},
		{"unregistered scope issued", (*suite).checkIssuedScope, faults{leakScope: true}, unregisteredScope},
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
		{name: "polling respects the interval"},
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
		TokenEndpoint: "https://issuer.example/t", EndSessionEndpoint: "https://issuer.example/e", JWKSURI: "https://issuer.example/k",
		CodeChallengeMethods: []string{"plain", "S256"},
	}
	if err := valid.validate("https://issuer.example"); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*discovery){
		"no authorization":       func(d *discovery) { d.AuthorizationEndpoint = "" },
		"no device":              func(d *discovery) { d.DeviceAuthorizationEndpoint = "" },
		"no token":               func(d *discovery) { d.TokenEndpoint = "" },
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

func TestCheckActive(t *testing.T) {
	now := time.Unix(1000, 0)
	valid := introspection.Result{
		Active: true, Issuer: "iss", Subject: "sub", ClientID: "client", Expiry: 2000, Audience: []string{"aud"},
	}
	if err := checkActive(valid, "iss", "client", "aud", now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*introspection.Result){
		"inactive":      func(r *introspection.Result) { r.Active = false },
		"issuer":        func(r *introspection.Result) { r.Issuer = "other" },
		"no subject":    func(r *introspection.Result) { r.Subject = "" },
		"client":        func(r *introspection.Result) { r.ClientID = "other" },
		"expired":       func(r *introspection.Result) { r.Expiry = 1000 },
		"two audiences": func(r *introspection.Result) { r.Audience = []string{"aud", "other"} },
	} {
		t.Run(name, func(t *testing.T) {
			result := valid
			change(&result)
			if err := checkActive(result, "iss", "client", "aud", now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestWantIssuedScope(t *testing.T) {
	registered := []string{"app:read", "app:write"}
	for scope, valid := range map[string]bool{
		"openid app:read app:write": true,
		"":                          false,
		"openid app:read":           false,
	} {
		if err := wantIssuedScope(scope, registered); (err == nil) != valid {
			t.Errorf("wantIssuedScope(%q) = %v, want valid %v", scope, err, valid)
		}
	}
}

func TestAuthorizationCode(t *testing.T) {
	const redirectURI, state = "https://holon.example/callback", "state"
	for name, test := range map[string]struct {
		redirect string
		want     string
	}{
		"code":         {"https://holon.example/callback?code=abc&state=state", "abc"},
		"other target": {"https://elsewhere.example/callback?code=abc&state=state", ""},
		"wrong state":  {"https://holon.example/callback?code=abc&state=other", ""},
		"error":        {"https://holon.example/callback?error=access_denied&state=state", ""},
	} {
		t.Run(name, func(t *testing.T) {
			redirect, err := url.Parse(test.redirect)
			if err != nil {
				t.Fatal(err)
			}
			got, err := authorizationCode(redirect, redirectURI, state)
			if got != test.want || (err == nil) != (test.want != "") {
				t.Fatalf("code %q, error %v", got, err)
			}
		})
	}
}

func TestValidateResult(t *testing.T) {
	now := time.Unix(1000, 0)
	can := scim.Capabilities{Invitations: true}
	for _, test := range []struct {
		name         string
		result       invitation.Result
		capabilities scim.Capabilities
		valid        bool
	}{
		{"sent", invitation.Result{UserID: "u", Sent: true, ExpiresAt: now.Add(time.Hour)}, can, true},
		{"no mail", invitation.Result{UserID: "u"}, scim.Capabilities{}, true},
		{"no user", invitation.Result{Sent: true, ExpiresAt: now.Add(time.Hour)}, can, false},
		{"not sent with the capability", invitation.Result{UserID: "u"}, can, false},
		{"already expired", invitation.Result{UserID: "u", Sent: true, ExpiresAt: now}, can, false},
		{"outlives the lifetime", invitation.Result{UserID: "u", Sent: true, ExpiresAt: now.Add(2 * time.Hour)}, can, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateResult(test.result, test.capabilities, time.Hour, now); (err == nil) != test.valid {
				t.Fatalf("validateResult = %v, want valid %v", err, test.valid)
			}
		})
	}
}
