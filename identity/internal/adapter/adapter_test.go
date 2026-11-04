package adapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientRejects(t *testing.T) {
	for _, test := range []struct{ name, endpoint, bearer string }{
		{"plain HTTP", "http://adapter.example", "secret"},
		{"no host", "https://", "secret"},
		{"user info", "https://user@adapter.example", "secret"},
		{"query", "https://adapter.example?x=1", "secret"},
		{"empty query", "https://adapter.example?", "secret"},
		{"fragment", "https://adapter.example#x", "secret"},
		{"too long", "https://adapter.example/" + strings.Repeat("a", 2048), "secret"},
		{"no bearer", "https://adapter.example", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewClient(test.endpoint, test.bearer, http.DefaultClient, time.Minute); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(t.Context(), http.MethodGet, "/", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status %d", response.StatusCode)
	}
}

func TestGuard(t *testing.T) {
	for _, test := range []struct {
		name, configured, credential string
		passed                       bool
	}{
		{name: "the bearer", configured: "secret", credential: "Bearer secret", passed: true},
		{name: "missing", configured: "secret"},
		{name: "wrong", configured: "secret", credential: "Bearer other"},
		{name: "prefix", configured: "secret", credential: "Bearer secretx"},
		{name: "unconfigured", credential: "Bearer "},
	} {
		t.Run(test.name, func(t *testing.T) {
			passed := false
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				passed = true
				if _, ok := r.Context().Deadline(); !ok {
					t.Error("no deadline")
				}
			})
			deny := func(w http.ResponseWriter) { w.WriteHeader(http.StatusTeapot) }
			request := httptest.NewRequestWithContext(t.Context(), "GET", "https://adapter.example/", nil)
			if test.credential != "" {
				request.Header.Set("Authorization", test.credential)
			}
			response := httptest.NewRecorder()
			Guard(test.configured, "realm", time.Minute, deny, next).ServeHTTP(response, request)
			if passed != test.passed {
				t.Fatalf("passed %v", passed)
			}
			if !test.passed && (response.Code != http.StatusTeapot || response.Header().Get("WWW-Authenticate") != `Bearer realm="realm"`) {
				t.Fatalf("status %d, challenge %q", response.Code, response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}
