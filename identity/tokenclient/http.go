package tokenclient

import (
	"context"
	"encoding/json"
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

// NewClient returns a client for the adapter at endpoint, the base URL for /v1/token-clients.
func NewClient(endpoint, bearer string, transport *http.Client) (*Client, error) {
	client, err := adapter.NewClient(endpoint, bearer, transport, requestTimeout)
	if err != nil {
		return nil, err
	}
	return &Client{adapter: client}, nil
}

// Create posts a request. A refusal is ErrInvalid; any other failure is ErrUnavailable.
// Retrying a request can create another client even when the first response was lost.
func (c *Client) Create(ctx context.Context, request Request) (Credentials, error) {
	body, _ := json.Marshal(request)
	response, err := c.adapter.Do(ctx, http.MethodPost, "/v1/token-clients", mediaType, mediaType, body)
	if err != nil {
		return Credentials{}, ErrUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusBadRequest {
		return Credentials{}, ErrInvalid
	}
	var credentials Credentials
	if response.StatusCode != http.StatusCreated || json.NewDecoder(response.Body).Decode(&credentials) != nil {
		return Credentials{}, ErrUnavailable
	}
	return credentials, nil
}

// Handler serves backend at POST /v1/token-clients. Every request carries the shared bearer.
func Handler(backend Backend, bearer string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/token-clients", func(w http.ResponseWriter, r *http.Request) {
		var request Request
		if adapter.Decode(http.MaxBytesReader(w, r.Body, maxBody), &request) != nil || !request.valid() {
			http.Error(w, "invalid token client", http.StatusBadRequest)
			return
		}
		credentials, err := backend.Create(r.Context(), request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", mediaType)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(credentials)
	})
	return adapter.Guard(bearer, "token-clients", requestTimeout, func(w http.ResponseWriter) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}, mux)
}
