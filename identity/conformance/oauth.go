package conformance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/holon-sh/protocol/identity/introspection"
)

const maxResponse = 1 << 20

var protocolScopes = []string{"openid", "profile", "email", "offline_access"}

type discovery struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	RevocationEndpoint          string   `json:"revocation_endpoint"`
	EndSessionEndpoint          string   `json:"end_session_endpoint"`
	JWKSURI                     string   `json:"jwks_uri"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuth           []string `json:"token_endpoint_auth_methods_supported"`
}

// validate applies the issuer comparison of [OpenID Connect Discovery 1.0 §4.3], the methods and revocation
// endpoint of [RFC 8414 §2] and the device endpoint of [RFC 8628 §4].
//
// [OpenID Connect Discovery 1.0 §4.3]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
// [RFC 8414 §2]: https://www.rfc-editor.org/rfc/rfc8414.html#section-2
// [RFC 8628 §4]: https://www.rfc-editor.org/rfc/rfc8628.html#section-4
func (d discovery) validate(issuer string) error {
	if d.Issuer != issuer {
		return fmt.Errorf("issuer %q, want %q", d.Issuer, issuer)
	}
	for name, endpoint := range map[string]string{
		"authorization_endpoint": d.AuthorizationEndpoint, "device_authorization_endpoint": d.DeviceAuthorizationEndpoint,
		"token_endpoint": d.TokenEndpoint, "revocation_endpoint": d.RevocationEndpoint, "end_session_endpoint": d.EndSessionEndpoint, "jwks_uri": d.JWKSURI,
	} {
		if !httpsEndpoint(endpoint) {
			return fmt.Errorf("%s %q is not an HTTPS URL", name, endpoint)
		}
	}
	if !slices.Contains(d.CodeChallengeMethods, "S256") {
		return fmt.Errorf("code_challenge_methods_supported %q lacks S256", d.CodeChallengeMethods)
	}
	if len(d.TokenEndpointAuth) != 0 && !slices.Contains(d.TokenEndpointAuth, "client_secret_basic") {
		return fmt.Errorf("token_endpoint_auth_methods_supported %q lacks client_secret_basic", d.TokenEndpointAuth)
	}
	return nil
}

func httpsEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func (s *suite) discover(ctx context.Context) (discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return discovery{}, err
	}
	var document discovery
	if err := s.send(req, &document); err != nil {
		return discovery{}, fmt.Errorf("discovery: %w", err)
	}
	return document, document.validate(s.cfg.Issuer)
}

type oauthClient struct{ id, secret string }

type token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type rejection struct {
	Status    int    `json:"-"`
	Challenge string `json:"-"`
	Code      string `json:"error"`
}

func (r *rejection) Error() string {
	return fmt.Sprintf("the request was refused: status %d, error %q", r.Status, r.Code)
}

// send decodes a 200 into output and answers any other status as *rejection. A nil output ignores the body, as a
// client does with the [RFC 7009 §2.2] response.
//
// [RFC 7009 §2.2]: https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2
func (s *suite) send(req *http.Request, output any) error {
	response, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	body := io.LimitReader(response.Body, maxResponse)
	if response.StatusCode != http.StatusOK {
		refused := &rejection{Status: response.StatusCode, Challenge: response.Header.Get("WWW-Authenticate")}
		_ = json.NewDecoder(body).Decode(refused)
		return refused
	}
	if output == nil {
		return nil
	}
	if err := json.NewDecoder(body).Decode(output); err != nil {
		return fmt.Errorf("response from %s: %w", req.URL, err)
	}
	return nil
}

func (s *suite) postForm(ctx context.Context, endpoint string, form url.Values, authenticate func(*http.Request), output any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authenticate(req)
	return s.send(req, output)
}

// post sends form to an issuer endpoint, authenticating a confidential client as [RFC 6749 §2.3.1] prescribes
// and answering a [RFC 6749 §5.2] refusal as *rejection.
//
// [RFC 6749 §2.3.1]: https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
// [RFC 6749 §5.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
func (s *suite) post(ctx context.Context, endpoint string, client oauthClient, form url.Values, output any) error {
	if client.secret == "" {
		form.Set("client_id", client.id)
	}
	return s.postForm(ctx, endpoint, form, func(req *http.Request) {
		if client.secret != "" {
			req.SetBasicAuth(url.QueryEscape(client.id), url.QueryEscape(client.secret))
		}
	}, output)
}

func (s *suite) exchange(ctx context.Context, client oauthClient, form url.Values) (token, error) {
	document, err := s.discover(ctx)
	if err != nil {
		return token{}, err
	}
	var issued token
	if err := s.post(ctx, document.TokenEndpoint, client, form, &issued); err != nil {
		return token{}, err
	}
	if issued.AccessToken == "" || !strings.EqualFold(issued.TokenType, "Bearer") {
		return token{}, fmt.Errorf("token response has no bearer access token: type %q", issued.TokenType)
	}
	return issued, nil
}

func (s *suite) browserClient() oauthClient {
	return oauthClient{id: s.cfg.BrowserClientID, secret: s.cfg.BrowserClientSecret}
}

// clientCredentials is the grant of [RFC 6749 §4.4], requested by the service account.
//
// [RFC 6749 §4.4]: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
func (s *suite) clientCredentials(ctx context.Context, resource string) (token, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if resource != "" {
		form.Set("resource", resource)
	}
	return s.exchange(ctx, oauthClient{id: s.cfg.ServiceAccountClientID, secret: s.cfg.ServiceAccountClientSecret}, form)
}

type grant struct {
	code, verifier string
}

// pkceChallenge is the S256 code challenge of [RFC 7636 §4.2].
//
// [RFC 7636 §4.2]: https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *suite) authorize(ctx context.Context, person SignInRequest) (grant, error) {
	document, err := s.discover(ctx)
	if err != nil {
		return grant{}, err
	}
	state, verifier := rand.Text(), rand.Text()+rand.Text()
	query := url.Values{
		"response_type": {"code"}, "client_id": {s.cfg.BrowserClientID}, "redirect_uri": {s.cfg.BrowserRedirectURI}, "scope": {"openid"},
		"state": {state}, "resource": {s.cfg.Resource.Audience}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	request := person
	request.AuthorizationURL = document.AuthorizationEndpoint + "?" + query.Encode()
	redirect, err := s.cfg.SignIn(ctx, request)
	if err != nil {
		return grant{}, fmt.Errorf("sign-in: %w", err)
	}
	code, err := authorizationCode(redirect, s.cfg.BrowserRedirectURI, state)
	if err != nil {
		return grant{}, err
	}
	return grant{code: code, verifier: verifier}, nil
}

// authorizationCode reads the [RFC 6749 §4.1.2] response from the URL the issuer redirected to.
//
// [RFC 6749 §4.1.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
func authorizationCode(redirect *url.URL, redirectURI, state string) (string, error) {
	if redirect == nil {
		return "", errors.New("sign-in hook answered no redirect")
	}
	target, _, _ := strings.Cut(redirect.String(), "?")
	if target != redirectURI {
		return "", fmt.Errorf("redirected to %q, want %q", target, redirectURI)
	}
	query := redirect.Query()
	if query.Get("state") != state {
		return "", fmt.Errorf("state %q, want %q", query.Get("state"), state)
	}
	if query.Get("code") == "" {
		return "", fmt.Errorf("no authorization code: error %q", query.Get("error"))
	}
	return query.Get("code"), nil
}

func (s *suite) redeem(ctx context.Context, issued grant) (token, error) {
	return s.exchange(ctx, s.browserClient(), url.Values{
		"grant_type": {"authorization_code"}, "code": {issued.code}, "redirect_uri": {s.cfg.BrowserRedirectURI},
		"code_verifier": {issued.verifier}, "resource": {s.cfg.Resource.Audience},
	})
}

func (s *suite) browserToken(ctx context.Context) (token, error) {
	issued, err := s.authorize(ctx, SignInRequest{})
	if err != nil {
		return token{}, err
	}
	return s.redeem(ctx, issued)
}

func (s *suite) wantActive(ctx context.Context, value, clientID, audience string) (introspection.Result, error) {
	result, err := s.introspector.Introspect(ctx, value)
	if err != nil {
		return result, err
	}
	if err := result.Check(s.cfg.Issuer, time.Now(), audience); err != nil {
		return result, err
	}
	if result.ClientID != clientID {
		return result, fmt.Errorf("client_id %q, want %q", result.ClientID, clientID)
	}
	return result, nil
}

func (s *suite) wantInactive(ctx context.Context, value, description string) error {
	result, err := s.introspector.Introspect(ctx, value)
	if err != nil {
		return err
	}
	if result.Active {
		return fmt.Errorf("a token %s is active", description)
	}
	return nil
}

func onlyRegistered(scope string, registered []string) error {
	for granted := range strings.FieldsSeq(scope) {
		if !slices.Contains(registered, granted) && !slices.Contains(protocolScopes, granted) {
			return fmt.Errorf("scope %q was granted but is not registered", granted)
		}
	}
	return nil
}
