package introspection

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

var _ Backend = (*Client)(nil)

type backendFunc func(context.Context, string) (Result, error)

func (f backendFunc) Introspect(ctx context.Context, token string) (Result, error) {
	return f(ctx, token)
}

func TestIntrospectionHandler(t *testing.T) {
	const bearer = "fixture-bearer"
	active := Result{
		Active: true, Subject: "user", Audience: "https://resource.example",
		Act: json.RawMessage(`{"iss":"https://issuer.example","sub":"service","team":"reports","act":{"sub":"prior"}}`),
	}
	valid := "Bearer " + bearer
	for _, test := range []struct {
		name, method, body, query string
		authorization             string
		result                    Result
		err                       error
		status                    int
	}{
		{name: "active token", body: "token=opaque", authorization: valid, result: active, status: 200},
		{
			name: "inactive metadata is removed", body: "token=opaque", authorization: valid,
			result: Result{Subject: "private", Act: json.RawMessage(`{"sub":"private-actor"}`)}, status: 200,
		},
		{name: "backend unavailable", body: "token=opaque", authorization: valid, err: errors.New("offline"), status: 503},
		{name: "wrong bearer", body: "token=opaque", authorization: "Bearer other", status: 401},
		{name: "method", method: "GET", authorization: valid, status: 405},
		{name: "query token", query: "?token=opaque", authorization: valid, status: 400},
		{name: "empty token", body: "token=", authorization: valid, status: 400},
		{name: "duplicate token", body: "token=opaque&token=other", authorization: valid, status: 400},
		{name: "token limit", body: "token=" + strings.Repeat("x", (16<<10)+1), authorization: valid, status: 400},
		{name: "body limit", body: "token=opaque&padding=" + strings.Repeat("x", 32<<10), authorization: valid, status: 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := Handler(backendFunc(func(_ context.Context, token string) (Result, error) {
				if token != "opaque" {
					t.Errorf("backend token=%q", token)
				}
				return test.result, test.err
			}), bearer)
			request := httptest.NewRequestWithContext(t.Context(), cmp.Or(test.method, "POST"), "https://identity.example/introspect"+test.query, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d; want %d: %s", response.Code, test.status, response.Body.String())
			}
			if test.status == http.StatusOK {
				if response.Header().Get("Content-Type") != "application/json" {
					t.Fatal("invalid introspection content type")
				}
				want := map[string]any{"active": false}
				if test.result.Active {
					want = map[string]any{
						"active": true, "token_type": "Bearer", "sub": "user", "aud": "https://resource.example",
						"act": map[string]any{"iss": "https://issuer.example", "sub": "service", "team": "reports", "act": map[string]any{"sub": "prior"}},
					}
				}
				var result map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !reflect.DeepEqual(result, want) {
					t.Fatalf("response=%s, want=%+v, error=%v", response.Body.Bytes(), want, err)
				}
			}
		})
	}
}

func TestClientReadsAnswers(t *testing.T) {
	complete := map[string]any{"active": true, "token_type": "Bearer", "iss": "i", "sub": "s", "client_id": "c", "exp": 2, "aud": "a"}
	const active = `{"active":true,"aud":"a","client_id":"c","exp":2,"iss":"i","sub":"s","token_type":"Bearer"}`
	const inactive = `{"active":false}`
	for _, test := range []struct {
		name    string
		change  map[string]any
		removed string
		status  int
		want    string
	}{
		{name: "token type in another case", change: map[string]any{"token_type": "bearer"}, want: active},
		{
			name: "additional claim", change: map[string]any{"identity_provider": "corp"},
			want: `{"active":true,"aud":"a","client_id":"c","exp":2,"identity_provider":"corp","iss":"i","sub":"s","token_type":"Bearer"}`,
		},
		{name: "inactive needs nothing else", change: map[string]any{"active": false}, removed: "sub", want: inactive},
		{name: "refresh token listing audiences", change: map[string]any{"token_type": "Refresh", "aud": []string{"a", "b"}}, want: inactive},
		{name: "no active", removed: "active"},
		{name: "no token type", removed: "token_type"},
		{name: "no issuer", removed: "iss"},
		{name: "no subject", removed: "sub"},
		{name: "no client", removed: "client_id"},
		{name: "no expiry", removed: "exp"},
		{name: "no audience", removed: "aud"},
		{name: "audience list", change: map[string]any{"aud": []string{"a"}}},
		{name: "scope outside the grammar", change: map[string]any{"scope": "read  write"}},
		{name: "nonboolean active", change: map[string]any{"active": "true"}},
		{name: "error status carrying an answer", change: map[string]any{"active": false}, status: http.StatusBadGateway},
		{name: "oversized answer", change: map[string]any{"padding": strings.Repeat("x", maxBody)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			answer := maps.Clone(complete)
			maps.Copy(answer, test.change)
			delete(answer, test.removed)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ParseForm() != nil || r.PostForm.Get("token") != "opaque" {
					t.Errorf("token=%q", r.PostForm.Get("token"))
				}
				w.WriteHeader(cmp.Or(test.status, http.StatusOK))
				_ = json.NewEncoder(w).Encode(answer)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "fixture-bearer", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Introspect(t.Context(), "opaque")
			if (err != nil) != (test.want == "") {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
			if got, _ := json.Marshal(result); test.want != "" && string(got) != test.want {
				t.Fatalf("decoded as %s, want %s", got, test.want)
			}
		})
	}
}

func TestClientKeepsTokensHandlerWouldRefuse(t *testing.T) {
	client, err := NewClient("https://adapter.invalid", "fixture-bearer", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", strings.Repeat("x", maxToken+1)} {
		if result, err := client.Introspect(t.Context(), token); err != nil || result.Active {
			t.Errorf("token of %d bytes: result=%+v, error=%v", len(token), result, err)
		}
	}
}

func TestResultCheck(t *testing.T) {
	now := time.Unix(1000, 0)
	valid := Result{Active: true, Issuer: "iss", Expiry: 2000, NotBefore: 1000, Audience: "aud"}
	if err := valid.Check("iss", now, "another", "aud"); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Result){
		"inactive":   func(r *Result) { r.Active = false },
		"issuer":     func(r *Result) { r.Issuer = "other" },
		"at expiry":  func(r *Result) { r.Expiry = 1000 },
		"before nbf": func(r *Result) { r.NotBefore = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			result := valid
			change(&result)
			if err := result.Check("iss", now, "another", "aud"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
