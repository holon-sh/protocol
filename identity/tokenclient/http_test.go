package tokenclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type backendFunc func(Request) (Credentials, error)

func (f backendFunc) Create(_ context.Context, r Request) (Credentials, error) { return f(r) }

func echoName(err error) http.Handler {
	return Handler(backendFunc(func(r Request) (Credentials, error) {
		return Credentials{ClientID: r.Name, ClientSecret: "secret"}, err
	}), "bearer")
}

func respond(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func TestCreate(t *testing.T) {
	longest := "  " + strings.Repeat("界", 253)
	for _, tt := range []struct {
		name, request, bearer string
		server                http.Handler
		want                  Credentials
		err                   error
	}{
		{"created with the name as supplied", longest, "bearer", echoName(nil), Credentials{ClientID: longest, ClientSecret: "secret"}, nil},
		{"too long", strings.Repeat("界", 256), "bearer", echoName(nil), Credentials{}, ErrInvalid},
		{"blank", " \t ", "bearer", echoName(nil), Credentials{}, ErrInvalid},
		{"backend failure", "Laptop", "bearer", echoName(errors.New("failure")), Credentials{}, ErrUnavailable},
		{"wrong bearer", "Laptop", "other", echoName(nil), Credentials{}, ErrUnavailable},
		{"success that isn't a creation", "Laptop", "bearer", respond(200, `{"client_id":"id","client_secret":"secret"}`), Credentials{}, ErrUnavailable},
		{"malformed", "Laptop", "bearer", respond(201, `{`), Credentials{}, ErrUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(tt.server)
			defer server.Close()
			client, err := NewClient(server.URL, tt.bearer, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Create(t.Context(), Request{Name: tt.request})
			if got != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("got %+v, %v; want %+v, %v", got, err, tt.want, tt.err)
			}
		})
	}
}

func TestHandlerWire(t *testing.T) {
	post := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(t.Context(), "POST", "/v1/token-clients", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer bearer")
		response := httptest.NewRecorder()
		echoName(nil).ServeHTTP(response, request)
		return response
	}
	created := post(`{"client_name":"Laptop"}`)
	if created.Code != http.StatusCreated || created.Header().Get("Content-Type") != "application/json" || created.Body.String() != `{"client_id":"Laptop","client_secret":"secret"}`+"\n" {
		t.Fatalf("status %d, %v: %s", created.Code, created.Header(), created.Body)
	}
	for _, body := range []string{
		`{"client_name":"Laptop","owner":"u"}`,
		`{"client_name":"Laptop"` + strings.Repeat(" ", maxBody) + `}`,
	} {
		if got := post(body).Code; got != http.StatusBadRequest {
			t.Errorf("%.40s: status %d", body, got)
		}
	}
}
