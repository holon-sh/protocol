package invitation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const bearer = "secret"

var _ Backend = (*Client)(nil)

type backendFunc func(Invitation) (Result, error)

func (f backendFunc) Invite(_ context.Context, invitation Invitation) (Result, error) {
	return f(invitation)
}

func TestLifetimeIsIntegerSeconds(t *testing.T) {
	data, err := json.Marshal(Invitation{Email: "a@example.test", Groups: []string{"g1"}, Lifetime: 90 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `{"email":"a@example.test","groups":["g1"],"lifetime":5400}`; got != want {
		t.Fatalf("marshal %s, want %s", got, want)
	}
	var invitation Invitation
	if err := json.Unmarshal(data, &invitation); err != nil {
		t.Fatal(err)
	}
	want := Invitation{Email: "a@example.test", Groups: []string{"g1"}, Lifetime: 90 * time.Minute}
	if !reflect.DeepEqual(invitation, want) {
		t.Fatalf("unmarshal %+v", invitation)
	}
	for _, body := range []string{
		`{"email":"a@example.test","lifetime":1.5}`,
		`{"email":"a@example.test","lifetime":9223372037}`,
		`{"email":"a@example.test","lifetime":3600,"role":"admin"}`,
	} {
		if err := json.Unmarshal([]byte(body), &invitation); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

func TestResultOmitsAZeroExpiry(t *testing.T) {
	data, err := json.Marshal(Result{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `{"userId":"u1","sent":false}`; got != want {
		t.Fatalf("marshal %s, want %s", got, want)
	}
}

func TestHandler(t *testing.T) {
	const valid = `{"email":"a@example.test","groups":["g1"],"lifetime":3600}`
	for _, test := range []struct {
		name, method, credential, contentType, body string
		backendErr                                  error
		status                                      int
		reached                                     bool
	}{
		{name: "invited", body: valid, status: 200, reached: true},
		{name: "refused by the backend", body: valid, backendErr: ErrInvalid, status: 400, reached: true},
		{name: "backend failure", body: valid, backendErr: errors.New("private provider failure"), status: 503, reached: true},
		{name: "wrong bearer", credential: "Bearer other", body: valid, status: 401},
		{name: "get", method: "GET", status: 405},
		{name: "content type", contentType: "text/plain", body: valid, status: 415},
		{name: "body limit", body: `{"email":"a@example.test","lifetime":3600,"groups":["` + strings.Repeat("g", maxBody) + `"]}`, status: 400},
		{name: "not an address", body: `{"email":"nobody","lifetime":3600}`, status: 400},
		{name: "display name", body: `{"email":"Ada <a@example.test>","lifetime":3600}`, status: 400},
		{name: "no lifetime", body: `{"email":"a@example.test"}`, status: 400},
		{name: "empty group", body: `{"email":"a@example.test","groups":[""],"lifetime":3600}`, status: 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			reached := false
			handler := Handler(backendFunc(func(Invitation) (Result, error) {
				reached = true
				return Result{UserID: "u1", Sent: true}, test.backendErr
			}), bearer)
			method := test.method
			if method == "" {
				method = "POST"
			}
			request := httptest.NewRequestWithContext(t.Context(), method, "https://adapter.example/v1/invitations", strings.NewReader(test.body))
			credential := test.credential
			if credential == "" {
				credential = "Bearer " + bearer
			}
			request.Header.Set("Authorization", credential)
			contentType := test.contentType
			if contentType == "" {
				contentType = "application/json"
			}
			request.Header.Set("Content-Type", contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || reached != test.reached {
				t.Fatalf("status %d, reached %v: %s", response.Code, reached, response.Body)
			}
			if test.status == http.StatusUnauthorized && response.Header().Get("WWW-Authenticate") != `Bearer realm="invitations"` {
				t.Errorf("challenge %q", response.Header().Get("WWW-Authenticate"))
			}
			if strings.Contains(response.Body.String(), "private") {
				t.Errorf("backend error leaked: %s", response.Body)
			}
		})
	}
}

func TestClient(t *testing.T) {
	expires := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		backend backendFunc
		want    Result
		err     error
	}{
		{
			name:    "sent",
			backend: func(Invitation) (Result, error) { return Result{UserID: "u1", Sent: true, ExpiresAt: expires}, nil },
			want:    Result{UserID: "u1", Sent: true, ExpiresAt: expires},
		},
		{name: "refused", backend: func(Invitation) (Result, error) { return Result{}, ErrInvalid }, err: ErrInvalid},
		{name: "unavailable", backend: func(Invitation) (Result, error) { return Result{}, errors.New("failure") }, err: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var seen Invitation
			server := httptest.NewTLSServer(Handler(backendFunc(func(invitation Invitation) (Result, error) {
				seen = invitation
				return test.backend(invitation)
			}), bearer))
			defer server.Close()
			client, err := NewClient(server.URL+"/", bearer, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			sent := Invitation{Email: "a@example.test", Groups: []string{"g1"}, Lifetime: time.Hour}
			got, err := client.Invite(t.Context(), sent)
			if !errors.Is(err, test.err) || !got.ExpiresAt.Equal(test.want.ExpiresAt) || got.UserID != test.want.UserID || got.Sent != test.want.Sent {
				t.Fatalf("invite %+v, %v; want %+v, %v", got, err, test.want, test.err)
			}
			if !reflect.DeepEqual(seen, sent) {
				t.Fatalf("backend saw %+v", seen)
			}
		})
	}
	t.Run("a malformed body is unavailable", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }))
		defer server.Close()
		client, err := NewClient(server.URL, bearer, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Invite(t.Context(), Invitation{Email: "a@example.test", Lifetime: time.Hour}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invite: %v", err)
		}
	})
}
