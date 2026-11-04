package introspection

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type backendFunc func(context.Context, string) (Result, error)

func (f backendFunc) Introspect(ctx context.Context, token string) (Result, error) {
	return f(ctx, token)
}

func TestIntrospectionHandler(t *testing.T) {
	const bearer = "fixture-bearer"
	active := Result{
		Active: true, TokenType: "Bearer", Subject: "user", Audience: []string{"https://resource.example"},
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
				switch test.status {
				case http.StatusBadRequest, http.StatusUnauthorized, http.StatusMethodNotAllowed:
					t.Fatal("rejected request reached introspection backend")
				}
				if token != "opaque" {
					t.Errorf("backend token=%q", token)
				}
				return test.result, test.err
			}), bearer)
			method := test.method
			if method == "" {
				method = "POST"
			}
			request := httptest.NewRequestWithContext(t.Context(), method, "https://identity.example/introspect"+test.query, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d; want %d: %s", response.Code, test.status, response.Body.String())
			}
			if challenge := response.Header().Get("WWW-Authenticate"); test.status == 401 && challenge != `Bearer realm="introspection"` {
				t.Errorf("challenge=%q", challenge)
			}
			if test.status == http.StatusOK {
				if response.Header().Get("Content-Type") != "application/json" {
					t.Fatal("invalid introspection content type")
				}
				want := map[string]any{"active": false}
				if test.result.Active {
					want = map[string]any{
						"active": true, "token_type": "Bearer", "sub": "user", "aud": []any{"https://resource.example"},
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
