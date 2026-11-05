package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/holon-sh/protocol/identity"
)

const (
	bearer      = "secret"
	userSchema  = `"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]`
	groupSchema = `"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]`
	patchSchema = `"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]`
)

func do(t *testing.T, handler http.Handler, method, target, credential, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, "https://adapter.example"+target, strings.NewReader(body))
	request.Header.Set("Authorization", credential)
	if body != "" {
		request.Header.Set("Content-Type", "application/scim+json; charset=utf-8")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func checkError(t *testing.T, response *httptest.ResponseRecorder, want, scimType string) {
	t.Helper()
	if got := response.Header().Get("Content-Type"); got != "application/scim+json" {
		t.Errorf("content type %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: %v", response.Body, err)
	}
	if !reflect.DeepEqual(body["schemas"], []any{"urn:ietf:params:scim:api:messages:2.0:Error"}) {
		t.Errorf("schemas %v", body["schemas"])
	}
	if body["status"] != want {
		t.Errorf("status %v, want %s", body["status"], want)
	}
	if got, _ := body["scimType"].(string); got != scimType {
		t.Errorf("scimType %q, want %q", got, scimType)
	}
}

func TestUnauthorizedRequestGetsTheErrorEnvelope(t *testing.T) {
	response := do(t, Handler(failingBackend{errors.New("backend reached")}, bearer), "GET", "/scim/v2/Users", "Bearer other", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", response.Code)
	}
	if got := response.Header().Get("WWW-Authenticate"); got != `Bearer realm="scim"` {
		t.Errorf("challenge %q", got)
	}
	checkError(t, response, "401", "")
}

func TestErrorEnvelope(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		code     int
		status   string
		scimType string
	}{
		{"filter", ErrFilter, 400, "400", "invalidFilter"},
		{"invalid", ErrInvalid, 400, "400", "invalidValue"},
		{"not found", ErrNotFound, 404, "404", ""},
		{"conflict", ErrConflict, 409, "409", "uniqueness"},
		{"unavailable", errors.New("private provider failure"), 503, "503", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := do(t, Handler(failingBackend{test.err}, bearer), "GET", "/scim/v2/Users/u1", "Bearer "+bearer, "")
			if response.Code != test.code {
				t.Fatalf("status %d: %s", response.Code, response.Body)
			}
			if strings.Contains(response.Body.String(), "private") {
				t.Errorf("backend error leaked: %s", response.Body)
			}
			checkError(t, response, test.status, test.scimType)
		})
	}
}

func TestFilters(t *testing.T) {
	const users, groups = "/scim/v2/Users", "/scim/v2/Groups"
	for _, test := range []struct {
		name, target, expression string
		want                     Filter
		rejected                 bool
	}{
		{name: "names ignore case", target: users, expression: `USERNAME EQ "a"`, want: Filter{UserName: "a"}},
		{name: "another attribute", target: users, expression: `displayName eq "a"`, rejected: true},
		{name: "another operator", target: users, expression: `userName ne "a"`, rejected: true},
		{name: "no value", target: users, expression: `userName eq`, rejected: true},
		{name: "unquoted value", target: users, expression: `userName eq a`, rejected: true},
		{name: "empty value", target: users, expression: `userName eq ""`, rejected: true},
		{name: "two spaces before the value", target: users, expression: `userName eq  "a"`, rejected: true},
		{name: "compound", target: users, expression: `userName eq "a" and active eq true`, rejected: true},
		{name: "value path", target: users, expression: `emails[value eq "a"]`, rejected: true},
		{name: "a user attribute on groups", target: groups, expression: `userName eq "a"`, rejected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeBackend()
			response := do(t, Handler(backend, bearer), "GET", test.target+"?filter="+url.QueryEscape(test.expression), "Bearer "+bearer, "")
			if test.rejected {
				if response.Code != http.StatusBadRequest || backend.start != 0 {
					t.Fatalf("status %d, backend reached %v", response.Code, backend.start != 0)
				}
				checkError(t, response, "400", "invalidFilter")
				return
			}
			if response.Code != http.StatusOK || backend.filter != test.want {
				t.Fatalf("status %d, backend filter %+v", response.Code, backend.filter)
			}
		})
	}
}

func TestPaginationBounds(t *testing.T) {
	for _, test := range []struct {
		name, query string
		start       int
		count       int
		rejected    bool
	}{
		{name: "defaults", start: 1, count: 200},
		{name: "explicit", query: "?startIndex=3&count=50", start: 3, count: 50},
		{name: "start below one", query: "?startIndex=0", start: 1, count: 200},
		{name: "count over cap", query: "?count=201", start: 1, count: 200},
		{name: "zero count", query: "?count=0", start: 1, count: 0},
		{name: "negative count", query: "?count=-1", start: 1, count: 0},
		{name: "text start", query: "?startIndex=one", rejected: true},
		{name: "text count", query: "?count=one", rejected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeBackend()
			response := do(t, Handler(backend, bearer), "GET", "/scim/v2/Users"+test.query, "Bearer "+bearer, "")
			if test.rejected {
				if response.Code != http.StatusBadRequest {
					t.Fatalf("status %d", response.Code)
				}
				checkError(t, response, "400", "invalidValue")
				return
			}
			if response.Code != http.StatusOK || backend.start != test.start || backend.count != test.count {
				t.Fatalf("status %d, start %d, count %d", response.Code, backend.start, backend.count)
			}
		})
	}
}

func TestListResponseEnvelope(t *testing.T) {
	backend := newFakeBackend()
	response := do(t, Handler(backend, bearer), "GET", "/scim/v2/Users?startIndex=4", "Bearer "+bearer, "")
	if got := response.Header().Get("Content-Type"); got != "application/scim+json" {
		t.Errorf("content type %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"schemas":      []any{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": float64(0), "startIndex": float64(4), "itemsPerPage": float64(0), "Resources": []any{},
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("empty list %v", body)
	}
	response = do(t, Handler(backend, bearer), "GET", "/scim/v2/Groups?count=1", "Bearer "+bearer, "")
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	resources := body["Resources"].([]any)
	group := resources[0].(map[string]any)
	if body["totalResults"] != float64(2) || body["itemsPerPage"] != float64(1) || len(resources) != 1 ||
		!reflect.DeepEqual(group["schemas"], []any{"urn:ietf:params:scim:schemas:core:2.0:Group"}) ||
		group["externalId"] != "Session/one" || group["displayName"] != "Session one" ||
		!reflect.DeepEqual(group["meta"], map[string]any{"resourceType": "Group"}) {
		t.Fatalf("group list %v", body)
	}
}

func TestCreateUser(t *testing.T) {
	t.Run("password is written and never returned", func(t *testing.T) {
		backend := newFakeBackend()
		response := do(t, Handler(backend, bearer), "POST", "/scim/v2/Users", "Bearer "+bearer,
			`{`+userSchema+`,"userName":"a@example.test","active":true,"password":"temporary"}`)
		if response.Code != http.StatusCreated {
			t.Fatalf("status %d: %s", response.Code, response.Body)
		}
		if got := response.Header().Get("Location"); got != "/scim/v2/Users/u1" {
			t.Errorf("location %q", got)
		}
		if strings.Contains(response.Body.String(), "temporary") || strings.Contains(response.Body.String(), `"password"`) {
			t.Errorf("password returned: %s", response.Body)
		}
		if backend.users["u1"].Password != "temporary" {
			t.Errorf("backend password %q", backend.users["u1"].Password)
		}
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		wantSchemas := []any{"urn:ietf:params:scim:schemas:core:2.0:User", "urn:holon:params:scim:schemas:extension:user:1.0"}
		if !reflect.DeepEqual(body["schemas"], wantSchemas) || body["id"] != "u1" ||
			!reflect.DeepEqual(body["urn:holon:params:scim:schemas:extension:user:1.0"], map[string]any{"pendingSetup": true}) ||
			!reflect.DeepEqual(body["meta"], map[string]any{"resourceType": "User"}) {
			t.Errorf("created %v", body)
		}
	})
	t.Run("read-only attributes are ignored", func(t *testing.T) {
		backend := newFakeBackend()
		response := do(t, Handler(backend, bearer), "POST", "/scim/v2/Users", "Bearer "+bearer, `{`+userSchema+`,"id":"chosen","userName":"a",`+
			`"groups":[{"value":"g1"}],"urn:holon:params:scim:schemas:extension:user:1.0":{"pendingSetup":false},"meta":{"resourceType":"Forged"}}`)
		if response.Code != http.StatusCreated {
			t.Fatalf("status %d: %s", response.Code, response.Body)
		}
		seen := backend.created
		if seen.ID != "" || seen.Groups != nil || seen.Holon != nil || seen.Meta != (Meta{}) {
			t.Fatalf("backend saw %+v", seen)
		}
	})
	t.Run("media type", func(t *testing.T) {
		request := httptest.NewRequestWithContext(t.Context(), "POST", "https://adapter.example/scim/v2/Users", strings.NewReader(`{`+userSchema+`,"userName":"a"}`))
		request.Header.Set("Authorization", "Bearer "+bearer)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		Handler(newFakeBackend(), bearer).ServeHTTP(response, request)
		if response.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d", response.Code)
		}
		checkError(t, response, "415", "")
	})
}

func TestCreateGroup(t *testing.T) {
	backend := newFakeBackend()
	response := do(t, Handler(backend, bearer), "POST", "/scim/v2/Groups", "Bearer "+bearer, `{`+groupSchema+`,"id":"chosen","externalId":"production/orders:read/install",`+
		`"displayName":"Forged","members":[{"value":"u1"}],"meta":{"resourceType":"Forged"}}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", response.Code, response.Body)
	}
	if got := response.Header().Get("Location"); got != "/scim/v2/Groups/g3" {
		t.Errorf("location %q", got)
	}
	if seen := backend.createdGroup; !reflect.DeepEqual(seen, Group{ExternalID: "production/orders:read/install"}) {
		t.Fatalf("backend saw %+v", seen)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"schemas": []any{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "id": "g3", "externalId": "production/orders:read/install",
		"displayName": "derived", "meta": map[string]any{"resourceType": "Group"},
	}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("created %v", body)
	}
}

func TestGroupPermissionSet(t *testing.T) {
	for _, test := range []struct {
		externalID string
		want       identity.PermissionSet
		err        error
	}{
		{externalID: "production/orders:read/install", want: identity.PermissionSet{Kind: "production/orders:read", UID: "install"}},
		{externalID: "", err: ErrInvalid},
		{externalID: "install", err: ErrInvalid},
		{externalID: "/install", err: ErrInvalid},
		{externalID: "production/orders:read/", err: ErrInvalid},
		{externalID: strings.Repeat("k", 257) + "/install", err: ErrInvalid},
	} {
		t.Run(test.externalID, func(t *testing.T) {
			set, err := Group{ExternalID: test.externalID}.PermissionSet()
			if set != test.want || !errors.Is(err, test.err) {
				t.Fatalf("PermissionSet() = %+v, %v", set, err)
			}
		})
	}
}

func TestRequestsAreValidatedBeforeTheBackend(t *testing.T) {
	for _, test := range []struct{ name, method, target, body, scimType string }{
		{"create without a schema", "POST", "/scim/v2/Users", `{"userName":"a"}`, "invalidSyntax"},
		{"create with an unknown attribute", "POST", "/scim/v2/Users", `{` + userSchema + `,"userName":"a","nickName":"b"}`, "invalidSyntax"},
		{"create over the body limit", "POST", "/scim/v2/Users", `{` + userSchema + `,"userName":"` + strings.Repeat("a", maxBody) + `"}`, "invalidSyntax"},
		{"create without a userName", "POST", "/scim/v2/Users", `{` + userSchema + `}`, "invalidValue"},
		{"patch without operations", "PATCH", "/scim/v2/Users/u1", `{` + patchSchema + `,"Operations":[]}`, "invalidSyntax"},
		{"patch with an unknown op", "PATCH", "/scim/v2/Users/u1", `{` + patchSchema + `,"Operations":[{"op":"move","path":"active","value":true}]}`, "invalidSyntax"},
		{"remove without a path", "PATCH", "/scim/v2/Users/u1", `{` + patchSchema + `,"Operations":[{"op":"remove"}]}`, "noTarget"},
		{"replace without a value", "PATCH", "/scim/v2/Users/u1", `{` + patchSchema + `,"Operations":[{"op":"replace","path":"active"}]}`, "invalidValue"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := do(t, Handler(failingBackend{errors.New("backend reached")}, bearer), test.method, test.target, "Bearer "+bearer, test.body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status %d", response.Code)
			}
			checkError(t, response, "400", test.scimType)
		})
	}
}

func TestServiceProviderConfigDocument(t *testing.T) {
	backend := newFakeBackend()
	backend.config = ServiceProviderConfig{
		Patch: Supported{Supported: true}, Filter: Filtering{Supported: true, MaxResults: 200},
		Holon: Capabilities{Invitations: true, Provider: "holon-cloud"},
	}
	response := do(t, Handler(backend, bearer), "GET", "/scim/v2/ServiceProviderConfig", "Bearer "+bearer, "")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatalf("status %d, content type %q", response.Code, response.Header().Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	unsupported := map[string]any{"supported": false}
	want := map[string]any{
		"schemas": []any{
			"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
			"urn:holon:params:scim:schemas:extension:capabilities:1.0",
		},
		"patch": map[string]any{"supported": true}, "bulk": unsupported, "changePassword": unsupported, "sort": unsupported, "etag": unsupported,
		"filter": map[string]any{"supported": true, "maxResults": float64(200)},
		"urn:holon:params:scim:schemas:extension:capabilities:1.0": map[string]any{"invitations": true, "provider": "holon-cloud"},
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("document %v", body)
	}
}

func TestUnservedOperationsAre501(t *testing.T) {
	handler := Handler(failingBackend{errors.New("backend reached")}, bearer)
	for _, target := range []string{"/scim/v2/Schemas", "/scim/v2/Groups/g1"} {
		response := do(t, handler, "GET", target, "Bearer "+bearer, "")
		if response.Code != http.StatusNotImplemented {
			t.Fatalf("%s: status %d", target, response.Code)
		}
		checkError(t, response, "501", "")
	}
}
