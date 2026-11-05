package invitation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/holon-sh/protocol/identity/internal/adapter"
)

const (
	mediaType      = "application/json"
	maxBody        = 64 << 10
	requestTimeout = 30 * time.Second
)

// Client calls Handler from Holon's side.
type Client struct {
	adapter *adapter.Client
}

// NewClient returns a Client for the adapter at endpoint, the base URL that /v1/invitations hangs from.
func NewClient(endpoint, bearer string, transport *http.Client) (*Client, error) {
	client, err := adapter.NewClient(endpoint, bearer, transport, requestTimeout)
	if err != nil {
		return nil, err
	}
	return &Client{adapter: client}, nil
}

// Invite posts invitation. A refusal is ErrInvalid; an authentication failure or any other status is
// ErrUnavailable.
func (c *Client) Invite(ctx context.Context, invitation Invitation) (Result, error) {
	body, _ := json.Marshal(invitation)
	response, err := c.adapter.Do(ctx, http.MethodPost, "/v1/invitations", mediaType, mediaType, body)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusBadRequest {
		return Result{}, ErrInvalid
	}
	var result Result
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, maxBody)).Decode(&result) != nil {
		return Result{}, ErrUnavailable
	}
	return result, nil
}

// Handler serves backend at POST /v1/invitations. Every request carries the shared bearer.
func Handler(backend Backend, bearer string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/invitations", func(w http.ResponseWriter, r *http.Request) {
		if !adapter.HasMediaType(r, mediaType) {
			http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
			return
		}
		var invitation Invitation
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&invitation) != nil || !invitation.valid() {
			http.Error(w, "invalid invitation", http.StatusBadRequest)
			return
		}
		result, err := backend.Invite(r.Context(), invitation)
		switch {
		case errors.Is(err, ErrInvalid):
			http.Error(w, "invalid invitation", http.StatusBadRequest)
		case err != nil:
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		default:
			w.Header().Set("Content-Type", mediaType)
			_ = json.NewEncoder(w).Encode(result)
		}
	})
	return adapter.Guard(bearer, "invitations", requestTimeout, func(w http.ResponseWriter) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}, mux)
}
