package introspection

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// Result uses [RFC 7662 §2.2] introspection fields; only active is universally required. The act extension
// is defined by [RFC 8693 §4.1].
//
// [RFC 7662 §2.2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
// [RFC 8693 §4.1]: https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
type Result struct {
	Active    bool                       `json:"active"`
	TokenType string                     `json:"token_type,omitempty"`
	Issuer    string                     `json:"iss,omitempty"`
	Subject   string                     `json:"sub,omitempty"`
	ClientID  string                     `json:"client_id,omitempty"`
	Expiry    int64                      `json:"exp,omitempty"`
	NotBefore int64                      `json:"nbf,omitempty"`
	Audience  []string                   `json:"aud,omitempty"`
	Scope     string                     `json:"scope,omitempty"`
	Act       json.RawMessage            `json:"act,omitempty"`
	Claims    map[string]json.RawMessage `json:"-"`
}

type Backend interface {
	Introspect(context.Context, string) (Result, error)
}

// Handler serves the [RFC 7662 §2] introspection endpoint. The caller authenticates with a bearer token, which
// [RFC 7662 §2.1] allows in place of client authentication; any other caller gets the [RFC 6750 §3] challenge.
//
// [RFC 7662 §2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2
// [RFC 7662 §2.1]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1
// [RFC 6750 §3]: https://www.rfc-editor.org/rfc/rfc6750.html#section-3
func Handler(backend Backend, bearer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bearer == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+bearer)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="introspection"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if r.ParseForm() != nil || len(r.PostForm["token"]) != 1 || r.PostForm.Get("token") == "" || len(r.PostForm.Get("token")) > 16<<10 {
			http.Error(w, "invalid token request", http.StatusBadRequest)
			return
		}
		result, err := backend.Introspect(r.Context(), r.PostForm.Get("token"))
		if err != nil {
			http.Error(w, "introspection unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}
