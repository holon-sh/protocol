package conformance

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/holon-sh/protocol"
	"github.com/holon-sh/protocol/identity"
	"github.com/holon-sh/protocol/identity/introspection"
	"github.com/holon-sh/protocol/identity/invitation"
	"github.com/holon-sh/protocol/identity/scim"
)

const (
	testBearer      = "bearer"
	browserClient   = "browser"
	browserSecret   = "browser secret"
	cliClient       = "cli"
	serviceClient   = "service account"
	serviceSecret   = "service secret"
	deviceInterval  = time.Second
	testResource    = "https://resource.example.test/"
	browserRedirect = "https://holon.example.test/.well-known/holon/callback"
	testGroup       = "group-1"
	callerPerson    = "caller"
	leakedScope     = "conformance:unregistered"
)

var (
	testScopes     = []string{"app:read", "app:write"}
	clientSecrets  = map[string]string{browserClient: browserSecret, serviceClient: serviceSecret, cliClient: ""}
	signedOutPages = map[string]protocol.Plane{
		"https://holon.example.test/?signedOut=1":       protocol.BasePlane,
		"https://admin.holon.example.test/?signedOut=1": protocol.AdminPlane,
		"https://dev.holon.example.test/?signedOut=1":   protocol.DevPlane,
	}
)

type faults struct {
	wrongIssuer                                          bool
	leakScope, scopeOnlyWhenNamed                        bool
	scopeDroppedAtIntrospection                          bool
	openIntrospection, activeUnknownToken                bool
	wrongClientID, wrongAudience                         bool
	pairwiseSubject, subjectNotUserID                    bool
	mintUnregistered, activeAfterDelete                  bool
	noResourceDefaults                                   bool
	filterIgnored, countIgnored, zeroCountReturnsAll     bool
	noPendingSetup, duplicateUserName, deleteKeeps       bool
	patchIgnored, membersIgnored                         bool
	noMail, sentWithoutCapability, inviteNewUserEachTime bool
	inviteDropsGroups                                    bool
	listDropsGroups                                      bool
	duplicateGroup                                       bool
	listDropsCreatedGroups                               bool
	anyVerifier                                          bool
	deviceApprovedEarly, deviceNoRefresh                 bool
	noCompleteVerificationURI, slowDownOnce              bool
	refreshInvalidGrant, revocationIgnored               bool
	refreshRefused                                       bool
	cliRefreshLosesAudience, cliRefreshAnyResource       bool
	signOutKeepsAccess, signOutKeepsRefresh              bool
	signedOutUnregistered                                protocol.Plane
	samePasswordAccepted, nameNotCollected, stillPending bool
	linkReusable, linkNeverExpires                       bool
}

type record struct {
	client, subject, audience, scope, session string
	generation                                int
	rotated                                   bool
}

type codeRecord struct {
	record

	redirectURI, challenge string
}

type deviceRecord struct {
	record

	userCode string
	approved bool
	interval time.Duration
	lastPoll time.Time
}

type fakeInvite struct {
	expires time.Time
	used    bool
}

type provider struct {
	faults  faults
	issuer  *httptest.Server
	adapter *httptest.Server

	mu          sync.Mutex
	skew        time.Duration
	next        int
	generations map[string]int
	scopes      map[string][]string
	tokens      map[string]record
	refreshes   map[string]record
	codes       map[string]codeRecord
	devices     map[string]*deviceRecord
	slowDowns   int
	users       map[string]*scim.User
	groups      []scim.Group
	members     map[string]bool
	invites     map[string]*fakeInvite
}

func newProvider(t *testing.T, f faults) *provider {
	t.Helper()
	p := &provider{
		faults:      f,
		generations: map[string]int{testResource: 1},
		scopes:      map[string][]string{testResource: testScopes},
		tokens:      map[string]record{},
		refreshes:   map[string]record{},
		codes:       map[string]codeRecord{},
		devices:     map[string]*deviceRecord{},
		users:       map[string]*scim.User{},
		members:     map[string]bool{},
		invites:     map[string]*fakeInvite{},
	}
	issuer := http.NewServeMux()
	issuer.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	issuer.HandleFunc("POST /token", p.token)
	issuer.HandleFunc("POST /device", p.deviceAuthorize)
	issuer.HandleFunc("POST /revoke", p.revoke)
	issuer.HandleFunc("GET /logout", p.logout)
	p.issuer = httptest.NewTLSServer(issuer)
	t.Cleanup(p.issuer.Close)
	adapter := http.NewServeMux()
	adapter.Handle("/scim/v2/", scim.Handler(p, testBearer))
	adapter.Handle("/v1/invitations", invitation.Handler(p, testBearer))
	adapter.Handle("/v1/resources/", identity.NewHandler(p, testBearer))
	adapter.HandleFunc("POST /introspect", p.introspect)
	p.adapter = httptest.NewTLSServer(adapter)
	t.Cleanup(p.adapter.Close)
	return p
}

func (p *provider) config() Config {
	return Config{
		Issuer: p.issuer.URL, Adapter: p.adapter.URL, Bearer: testBearer,
		BrowserClientID: browserClient, BrowserClientSecret: browserSecret, CLIClientID: cliClient,
		ServiceAccountClientID: serviceClient, ServiceAccountClientSecret: serviceSecret,
		Resource: Resource{Audience: testResource, Scopes: testScopes},
		HTTP:     p.issuer.Client(), BrowserRedirectURI: browserRedirect, SignIn: p.signIn,
	}
}

func (p *provider) now() time.Time {
	return time.Now().Add(p.skew)
}

func (p *provider) advance(_ context.Context, duration time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.skew += duration
	return nil
}

func (p *provider) id(prefix string) string {
	p.next++
	return prefix + strconv.Itoa(p.next)
}

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	base := p.issuer.URL
	document := discovery{
		Issuer: base, AuthorizationEndpoint: base + "/authorize", DeviceAuthorizationEndpoint: base + "/device", TokenEndpoint: base + "/token",
		RevocationEndpoint: base + "/revoke", EndSessionEndpoint: base + "/logout", JWKSURI: base + "/keys", CodeChallengeMethods: []string{"S256"},
		TokenEndpointAuth: []string{"client_secret_basic"},
	}
	if p.faults.wrongIssuer {
		document.Issuer = base + "/other"
	}
	_ = json.NewEncoder(w).Encode(document)
}

func refuse(w http.ResponseWriter, code string) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (p *provider) issue(w http.ResponseWriter, r record, refresh bool) {
	value := p.id("token-")
	p.tokens[value] = r
	response := token{AccessToken: value, TokenType: "bearer", Scope: r.scope}
	if slices.Contains(strings.Fields(r.scope), "openid") {
		response.IDToken = r.session
	}
	if refresh {
		response.RefreshToken = p.id("refresh-")
		p.refreshes[response.RefreshToken] = r
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (p *provider) limit(audience, requested string) string {
	granted := slices.DeleteFunc(strings.Fields(requested), func(scope string) bool { return !slices.Contains(protocolScopes, scope) })
	if !p.faults.scopeOnlyWhenNamed {
		granted = append(granted, p.scopes[audience]...)
	}
	if p.faults.leakScope {
		granted = append(granted, leakedScope)
	}
	return strings.Join(granted, " ")
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = r.ParseForm()
	id, secret, _ := r.BasicAuth()
	id, _ = url.QueryUnescape(id)
	secret, _ = url.QueryUnescape(secret)
	client := cmp.Or(id, r.PostForm.Get("client_id"))
	if want, known := clientSecrets[client]; !known || secret != want {
		refuse(w, "invalid_client")
		return
	}
	resource := r.PostForm.Get("resource")
	if resource == "" && p.faults.noResourceDefaults {
		resource = testResource
	}
	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		p.clientCredentials(w, client, resource)
	case "authorization_code":
		p.redeemCode(w, client, resource, r.PostForm)
	case "refresh_token":
		p.refresh(w, client, resource, r.PostForm.Get("refresh_token"))
	case deviceGrantType:
		p.pollDevice(w, resource, r.PostForm.Get("device_code"))
	default:
		refuse(w, "unsupported_grant_type")
	}
}

func (p *provider) clientCredentials(w http.ResponseWriter, client, resource string) {
	generation, registered := p.generations[resource]
	if !registered && !p.faults.mintUnregistered {
		refuse(w, "invalid_target")
		return
	}
	p.issue(w, record{client: client, subject: "service", audience: resource, scope: p.limit(resource, ""), generation: generation}, false)
}

func (p *provider) redeemCode(w http.ResponseWriter, client, resource string, form url.Values) {
	code, ok := p.codes[form.Get("code")]
	delete(p.codes, form.Get("code"))
	if !ok || code.client != client || code.audience != resource || code.redirectURI != form.Get("redirect_uri") {
		refuse(w, "invalid_grant")
		return
	}
	if !p.faults.anyVerifier && pkceChallenge(form.Get("code_verifier")) != code.challenge {
		refuse(w, "invalid_grant")
		return
	}
	p.issue(w, code.record, true)
}

func (p *provider) refresh(w http.ResponseWriter, client, resource, value string) {
	previous, ok := p.refreshes[value]
	if !ok || previous.client != client || p.faults.refreshRefused {
		refuse(w, "invalid_grant")
		return
	}
	if resource != previous.audience && !(client == cliClient && p.faults.cliRefreshAnyResource) {
		code := "invalid_target"
		if p.faults.refreshInvalidGrant {
			code = "invalid_grant"
		}
		refuse(w, code)
		return
	}
	if client == cliClient && previous.rotated && p.faults.cliRefreshLosesAudience {
		previous.audience = ""
	}
	previous.rotated = true
	delete(p.refreshes, value)
	p.issue(w, previous, true)
}

func (p *provider) revoke(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = r.ParseForm()
	if r.PostForm.Get("client_id") != cliClient {
		refuse(w, "invalid_client")
		return
	}
	if !p.faults.revocationIgnored {
		delete(p.refreshes, r.PostForm.Get("token"))
	}
}

func (p *provider) logout(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	query := r.URL.Query()
	target := query.Get("post_logout_redirect_uri")
	plane, registered := signedOutPages[target]
	if !registered || plane == p.faults.signedOutUnregistered || query.Get("client_id") != browserClient {
		refuse(w, "invalid_request")
		return
	}
	inSession := func(_ string, r record) bool { return r.session == query.Get("id_token_hint") }
	if !p.faults.signOutKeepsAccess {
		maps.DeleteFunc(p.tokens, inSession)
	}
	if !p.faults.signOutKeepsRefresh {
		maps.DeleteFunc(p.refreshes, inSession)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (p *provider) deviceAuthorize(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = r.ParseForm()
	if r.PostForm.Get("client_id") != cliClient {
		refuse(w, "invalid_client")
		return
	}
	audience := r.PostForm.Get("resource")
	if len(r.PostForm["resource"]) != 1 || audience == "" {
		refuse(w, "invalid_target")
		return
	}
	code, userCode := p.id("device-"), p.id("user-code-")
	p.devices[code] = &deviceRecord{
		record: record{
			client: cliClient, subject: callerPerson, audience: audience, scope: p.limit(audience, r.PostForm.Get("scope")),
			generation: p.generations[audience],
		},
		userCode: userCode, interval: deviceInterval,
	}
	response := deviceAuthorization{
		DeviceCode: code, UserCode: userCode, VerificationURI: p.issuer.URL + "/verify",
		VerificationURIComplete: p.issuer.URL + "/verify?user_code=" + userCode, ExpiresIn: 30, Interval: int(deviceInterval / time.Second),
	}
	if p.faults.noCompleteVerificationURI {
		response.VerificationURIComplete = ""
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (p *provider) pollDevice(w http.ResponseWriter, resource, code string) {
	device, ok := p.devices[code]
	if !ok {
		refuse(w, "invalid_grant")
		return
	}
	if resource != device.audience {
		refuse(w, "invalid_target")
		return
	}
	tooFast := p.now().Sub(device.lastPoll) < device.interval
	device.lastPoll = p.now()
	switch {
	case tooFast || (p.faults.slowDownOnce && device.approved && p.slowDowns == 0):
		device.interval += slowDownIncrement
		p.slowDowns++
		refuse(w, "slow_down")
	case !device.approved && !p.faults.deviceApprovedEarly:
		refuse(w, "authorization_pending")
	default:
		delete(p.devices, code)
		p.issue(w, device.record, !p.faults.deviceNoRefresh && slices.Contains(strings.Fields(device.scope), "offline_access"))
	}
}

func (p *provider) approveDevice(request SignInRequest) error {
	for _, device := range p.devices {
		if device.userCode == request.UserCode {
			device.approved = true
			return nil
		}
	}
	return errors.New("unknown user code")
}

func (p *provider) introspect(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.faults.openIntrospection && r.Header.Get("Authorization") != "Bearer "+testBearer {
		w.Header().Set("WWW-Authenticate", `Bearer realm="introspection"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_ = r.ParseForm()
	token, known := p.tokens[r.PostForm.Get("token")]
	generation, registered := p.generations[token.audience]
	active := known && (p.faults.activeAfterDelete || (registered && generation == token.generation))
	if !known && p.faults.activeUnknownToken {
		token, active = record{client: serviceClient, subject: "service", audience: testResource}, true
	}
	if p.faults.wrongClientID {
		token.client = "another client"
	}
	if p.faults.wrongAudience {
		token.audience = "https://another.example.test/"
	}
	if p.faults.pairwiseSubject && token.client == cliClient {
		token.subject = "pairwise " + token.subject
	}
	if p.faults.scopeDroppedAtIntrospection {
		token.scope = strings.Join(slices.DeleteFunc(strings.Fields(token.scope), func(scope string) bool { return !slices.Contains(protocolScopes, scope) }), " ")
	}
	var result introspection.Result
	if active {
		result = introspection.Result{
			Active: true, Issuer: p.issuer.URL, Subject: token.subject, ClientID: token.client,
			Expiry: p.now().Add(time.Hour).Unix(), Audience: token.audience, Scope: token.scope,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (p *provider) Ensure(_ context.Context, spec identity.Spec) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.generations[spec.Audience]; !ok {
		p.next++
		p.generations[spec.Audience] = p.next
	}
	p.scopes[spec.Audience] = spec.Scopes
	return nil
}

func (p *provider) Delete(_ context.Context, spec identity.Spec) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.generations, spec.Audience)
	delete(p.scopes, spec.Audience)
	return nil
}

func (p *provider) signIn(_ context.Context, request SignInRequest) (*url.URL, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if request.Invitation {
		return &url.URL{}, p.followLink(request)
	}
	if strings.HasPrefix(request.AuthorizationURL, p.issuer.URL+"/verify") {
		return nil, p.approveDevice(request)
	}
	subject := callerPerson
	if request.UserName != "" {
		user := p.byName(request.UserName)
		if user == nil || user.Password != request.Password {
			return nil, errors.New("wrong credentials")
		}
		if user.Holon.PendingSetup {
			if err := p.finishSetup(user, request); err != nil {
				return nil, err
			}
		}
		subject = user.ID
		if p.faults.subjectNotUserID {
			subject = "subject-" + user.ID
		}
	}
	authorization, _ := url.Parse(request.AuthorizationURL)
	query := authorization.Query()
	if query.Get("code_challenge_method") != "S256" {
		return nil, errors.New("PKCE S256 is required")
	}
	audience := query.Get("resource")
	code := p.id("code-")
	p.codes[code] = codeRecord{
		record: record{
			client: query.Get("client_id"), subject: subject, audience: audience, scope: p.limit(audience, query.Get("scope")),
			generation: p.generations[audience], session: p.id("session-"),
		},
		redirectURI: query.Get("redirect_uri"), challenge: query.Get("code_challenge"),
	}
	redirect, _ := url.Parse(query.Get("redirect_uri"))
	redirect.RawQuery = url.Values{"code": {code}, "state": {query.Get("state")}}.Encode()
	return redirect, nil
}

func (p *provider) finishSetup(user *scim.User, request SignInRequest) error {
	if request.NewPassword == user.Password && !p.faults.samePasswordAccepted {
		return errors.New("the new password must differ")
	}
	user.Password = request.NewPassword
	user.Holon.PendingSetup = p.faults.stillPending
	if !p.faults.nameNotCollected {
		user.Name = request.Name
	}
	return nil
}

func (p *provider) followLink(request SignInRequest) error {
	invite, ok := p.invites[request.UserName]
	if !ok {
		return errors.New("no message was sent")
	}
	if !p.faults.linkNeverExpires && p.now().After(invite.expires) {
		return errors.New("the link expired")
	}
	if !p.faults.linkReusable && invite.used {
		return errors.New("the link was used")
	}
	invite.used = true
	return p.finishSetup(p.byName(request.UserName), request)
}

func (p *provider) byName(name string) *scim.User {
	for _, user := range p.users {
		if user.UserName == name {
			return user
		}
	}
	return nil
}

func (p *provider) view(user *scim.User) scim.User {
	view := *user
	if p.faults.noPendingSetup {
		view.Holon = nil
	}
	if p.members[user.ID] {
		view.Groups = []scim.Ref{{Value: testGroup}}
	}
	return view
}

func (p *provider) Capabilities(context.Context) (scim.Capabilities, error) {
	return scim.Capabilities{Invitations: !p.faults.noMail && !p.faults.sentWithoutCapability}, nil
}

func (p *provider) FindUser(_ context.Context, userName string) (scim.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, user := range p.users {
		view := p.view(user)
		if p.faults.filterIgnored || view.UserName == userName {
			return view, nil
		}
	}
	return scim.User{}, scim.ErrNotFound
}

func (p *provider) ListUsers(_ context.Context, start, count int) (scim.Page[scim.User], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var matches []scim.User
	for _, user := range p.users {
		view := p.view(user)
		if p.faults.listDropsGroups {
			view.Groups = nil
		}
		matches = append(matches, view)
	}
	slices.SortFunc(matches, func(a, b scim.User) int { return strings.Compare(a.ID, b.ID) })
	if p.faults.countIgnored && count != 0 || p.faults.zeroCountReturnsAll && count == 0 {
		count = len(matches)
	}
	from := min(start-1, len(matches))
	return scim.Page[scim.User]{TotalResults: len(matches), Resources: matches[from:min(from+count, len(matches))]}, nil
}

func (p *provider) GetUser(_ context.Context, id string) (scim.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	user, ok := p.users[id]
	if !ok {
		return scim.User{}, scim.ErrNotFound
	}
	return p.view(user), nil
}

func (p *provider) CreateUser(_ context.Context, user scim.User) (scim.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byName(user.UserName) != nil && !p.faults.duplicateUserName {
		return scim.User{}, scim.ErrConflict
	}
	return p.view(p.add(user)), nil
}

func (p *provider) add(user scim.User) *scim.User {
	created := user
	created.ID = p.id("user-")
	created.Holon = &scim.UserExtension{PendingSetup: user.Password != ""}
	p.users[created.ID] = &created
	return &created
}

func (p *provider) PatchUser(_ context.Context, id string, patch scim.Patch) (scim.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	user, ok := p.users[id]
	if !ok {
		return scim.User{}, scim.ErrNotFound
	}
	if p.faults.patchIgnored {
		return p.view(user), nil
	}
	for _, operation := range patch.Operations {
		switch operation.Path {
		case "active":
			_ = json.Unmarshal(operation.Value, &user.Active)
		case "name":
			_ = json.Unmarshal(operation.Value, &user.Name)
		case "password":
			_ = json.Unmarshal(operation.Value, &user.Password)
			user.Holon.PendingSetup = true
		default:
			return scim.User{}, scim.ErrInvalid
		}
	}
	return p.view(user), nil
}

func (p *provider) DeleteUser(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.users[id]; !ok {
		return scim.ErrNotFound
	}
	if !p.faults.deleteKeeps {
		delete(p.users, id)
	}
	return nil
}

func (p *provider) ListGroups(_ context.Context, start, count int) (scim.Page[scim.Group], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	groups := []scim.Group{{ID: testGroup, ExternalID: "Session/one", DisplayName: "Session one"}}
	if !p.faults.listDropsCreatedGroups {
		groups = append(groups, p.groups...)
	}
	from := min(start-1, len(groups))
	return scim.Page[scim.Group]{TotalResults: len(groups), Resources: groups[from:min(from+count, len(groups))]}, nil
}

func (p *provider) CreateGroup(_ context.Context, set identity.PermissionSet) (scim.Group, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	externalID := set.Kind + "/" + set.UID
	if !p.faults.duplicateGroup {
		for _, existing := range p.groups {
			if existing.ExternalID == externalID {
				return scim.Group{}, scim.ErrConflict
			}
		}
	}
	created := scim.Group{ID: p.id("set-"), ExternalID: externalID, DisplayName: set.Kind + " " + set.UID}
	p.groups = append(p.groups, created)
	return created, nil
}

func (p *provider) PatchGroup(_ context.Context, id string, patch scim.Patch) (scim.Group, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if id != testGroup {
		return scim.Group{}, scim.ErrNotFound
	}
	for _, operation := range patch.Operations {
		switch {
		case p.faults.membersIgnored:
		case operation.Op == "add" && operation.Path == "members":
			var refs []scim.Ref
			_ = json.Unmarshal(operation.Value, &refs)
			for _, ref := range refs {
				p.members[ref.Value] = true
			}
		case operation.Op == "remove" && strings.HasPrefix(operation.Path, `members[value eq "`):
			member := strings.TrimSuffix(strings.TrimPrefix(operation.Path, `members[value eq "`), `"]`)
			delete(p.members, member)
		default:
			return scim.Group{}, scim.ErrInvalid
		}
	}
	return scim.Group{ID: id}, nil
}

func (p *provider) Invite(_ context.Context, request invitation.Invitation) (invitation.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	user := p.byName(request.Email)
	if user == nil || p.faults.inviteNewUserEachTime {
		user = p.add(scim.User{UserName: request.Email, Active: true})
		user.Holon.PendingSetup = true
	}
	if !p.faults.inviteDropsGroups && slices.Contains(request.Groups, testGroup) {
		p.members[user.ID] = true
	}
	if p.faults.noMail {
		return invitation.Result{UserID: user.ID}, nil
	}
	expires := p.now().Add(request.Lifetime)
	p.invites[request.Email] = &fakeInvite{expires: expires}
	return invitation.Result{UserID: user.ID, Sent: true, ExpiresAt: expires}, nil
}
