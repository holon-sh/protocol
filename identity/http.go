package identity

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxBody = 64 << 10
const registrationTimeout = 2 * time.Minute

type Client struct {
	endpoint, bearer string
	http             *http.Client
}

func NewClient(endpoint, bearer string, transport *http.Client) (*Client, error) {
	if !httpsURL(endpoint) || bearer == "" {
		return nil, errors.New("HTTPS endpoint and bearer credential are required")
	}
	client := *transport
	client.Timeout = registrationTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: strings.TrimSuffix(endpoint, "/"), bearer: bearer, http: &client}, nil
}

func (c *Client) Ensure(ctx context.Context, spec Spec) error {
	return c.call(ctx, "ensure", spec)
}

func (c *Client) Delete(ctx context.Context, spec Spec) error {
	return c.call(ctx, "delete", spec)
}

func (c *Client) call(ctx context.Context, operation string, spec Spec) error {
	body, _ := json.Marshal(Request{Spec: spec})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/resources/"+operation, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
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
	operations := map[string]func(context.Context, Spec) error{
		"ensure": backend.Ensure,
		"delete": backend.Delete,
	}
	mux := http.NewServeMux()
	for operation, run := range operations {
		mux.HandleFunc("POST /v1/resources/"+operation, func(w http.ResponseWriter, r *http.Request) {
			if bearer == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+bearer)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
				http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
				return
			}
			var request Request
			if decode(http.MaxBytesReader(w, r.Body, maxBody), &request) != nil || request.Spec.Validate() != nil {
				http.Error(w, "invalid resource", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), registrationTimeout)
			defer cancel()
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(registrationTimeout))
			err := run(ctx, request.Spec)
			switch {
			case errors.Is(err, ErrOwnership):
				http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			case err != nil:
				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		})
	}
	return mux
}

func decode(body io.Reader, output any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}
