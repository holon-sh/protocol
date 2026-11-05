package introspection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/holon-sh/protocol/identity/internal/adapter"
)

const (
	requestTimeout = 10 * time.Second
	maxToken       = 16 << 10
	maxBody        = 64 << 10
)

// Result is the [RFC 7662 §2.2] answer package profile requires: empty when inactive, otherwise about a Bearer token.
// The act extension is defined by [RFC 8693 §4.1].
//
// [RFC 7662 §2.2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
// [RFC 8693 §4.1]: https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
type Result struct {
	Active    bool                       `json:"active"`
	Issuer    string                     `json:"iss,omitempty"`
	Subject   string                     `json:"sub,omitempty"`
	ClientID  string                     `json:"client_id,omitempty"`
	Expiry    int64                      `json:"exp,omitempty"`
	NotBefore int64                      `json:"nbf,omitempty"`
	Audience  string                     `json:"aud,omitempty"`
	Scope     string                     `json:"scope,omitempty"`
	Act       json.RawMessage            `json:"act,omitempty"`
	Claims    map[string]json.RawMessage `json:"-"`
}

type Backend interface {
	Introspect(context.Context, string) (Result, error)
}

type Client struct {
	adapter *adapter.Client
}

func NewClient(endpoint, bearer string, transport *http.Client) (*Client, error) {
	client, err := adapter.NewClient(endpoint, bearer, transport, requestTimeout)
	if err != nil {
		return nil, err
	}
	return &Client{adapter: client}, nil
}

// Introspect posts token to Handler as [RFC 7662 §2.1] describes. A token Handler would refuse for its size cannot
// exist, so it is not active, as [RFC 7662 §2.2] says of such a token. Any status but 200, or an answer that does not
// decode, is an error.
//
// [RFC 7662 §2.1]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1
// [RFC 7662 §2.2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
func (c *Client) Introspect(ctx context.Context, token string) (Result, error) {
	if token == "" || len(token) > maxToken {
		return Result{}, nil
	}
	body := url.Values{"token": {token}}.Encode()
	response, err := c.adapter.Do(ctx, http.MethodPost, "/introspect", "application/json", "application/x-www-form-urlencoded", []byte(body))
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("introspection answered status %d", response.StatusCode)
	}
	var result Result
	if err := json.NewDecoder(io.LimitReader(response.Body, maxBody)).Decode(&result); err != nil {
		return Result{}, fmt.Errorf("introspection answer: %w", err)
	}
	return result, nil
}

// Handler serves the [RFC 7662 §2] introspection endpoint. The caller authenticates with a bearer token, which
// [RFC 7662 §2.1] allows in place of client authentication.
//
// [RFC 7662 §2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2
// [RFC 7662 §2.1]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1
func Handler(backend Backend, bearer string) http.Handler {
	return adapter.Guard(bearer, "introspection", requestTimeout, func(w http.ResponseWriter) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if r.ParseForm() != nil || len(r.PostForm["token"]) != 1 || r.PostForm.Get("token") == "" || len(r.PostForm.Get("token")) > maxToken {
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
	}))
}
