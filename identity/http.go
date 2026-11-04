package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/holon-sh/protocol/identity/internal/adapter"
)

const (
	maxBody             = 64 << 10
	registrationTimeout = 2 * time.Minute
)

type Client struct {
	adapter *adapter.Client
}

func NewClient(endpoint, bearer string, transport *http.Client) (*Client, error) {
	client, err := adapter.NewClient(endpoint, bearer, transport, registrationTimeout)
	if err != nil {
		return nil, err
	}
	return &Client{adapter: client}, nil
}

func (c *Client) Ensure(ctx context.Context, spec Spec) error {
	return c.call(ctx, "ensure", spec)
}

func (c *Client) Delete(ctx context.Context, spec Spec) error {
	return c.call(ctx, "delete", spec)
}

func (c *Client) call(ctx context.Context, operation string, spec Spec) error {
	body, _ := json.Marshal(registration{Spec: spec})
	response, err := c.adapter.Do(ctx, http.MethodPost, "/v1/resources/"+operation, "application/json", body)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusConflict {
		return ErrOwnership
	}
	if response.StatusCode != http.StatusNoContent {
		return ErrUnavailable
	}
	return nil
}

func NewHandler(backend Backend, bearer string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/resources/ensure", serve(backend.Ensure))
	mux.HandleFunc("POST /v1/resources/delete", serve(backend.Delete))
	return adapter.Guard(bearer, "registration", registrationTimeout, func(w http.ResponseWriter) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}, mux)
}

func serve(run func(context.Context, Spec) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adapter.HasMediaType(r, "application/json") {
			http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
			return
		}
		var request registration
		if adapter.Decode(http.MaxBytesReader(w, r.Body, maxBody), &request) != nil || request.Spec.Validate() != nil {
			http.Error(w, "invalid resource", http.StatusBadRequest)
			return
		}
		err := run(r.Context(), request.Spec)
		switch {
		case errors.Is(err, ErrOwnership):
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
		case err != nil:
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
