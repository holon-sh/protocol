// Package tokenclient creates the OAuth client through which one personal API token is minted.
// Its wire members are named after [RFC 7591 §2] and [RFC 7591 §3.2.1]; the shared bearer stands in
// for the initial access token. The backend fixes the other client properties, including a
// 30-day access token lifetime. This is not an RFC 7591 registration endpoint.
//
// [RFC 7591 §2]: https://www.rfc-editor.org/rfc/rfc7591.html#section-2
// [RFC 7591 §3.2.1]: https://www.rfc-editor.org/rfc/rfc7591.html#section-3.2.1
package tokenclient

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("token client invalid")
	ErrUnavailable = errors.New("token client unavailable")
)

// Request names the client. Names may be reused and are stored as supplied.
type Request struct {
	Name string `json:"client_name"`
}

// Credentials identify the created client and contain its secret.
type Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// Backend creates a client for one personal token. Create is not idempotent: every successful
// call creates a new client.
type Backend interface {
	Create(context.Context, Request) (Credentials, error)
}

func (r Request) valid() bool {
	return strings.TrimSpace(r.Name) != "" && utf8.RuneCountInString(r.Name) <= 255
}
