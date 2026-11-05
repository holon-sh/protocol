package adapter

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	endpoint, bearer string
	http             *http.Client
}

func NewClient(endpoint, bearer string, transport *http.Client, timeout time.Duration) (*Client, error) {
	if !HTTPSURL(endpoint) || bearer == "" {
		return nil, errors.New("HTTPS endpoint and bearer credential are required")
	}
	return &Client{endpoint: strings.TrimSuffix(endpoint, "/"), bearer: bearer, http: NoRedirects(transport, timeout)}, nil
}

func NoRedirects(transport *http.Client, timeout time.Duration) *http.Client {
	client := *transport
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

func (c *Client) Do(ctx context.Context, method, path, accept, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	req.Header.Set("Accept", accept)
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	return c.http.Do(req)
}

// Guard answers a request without the shared bearer with deny and the challenge of [RFC 6750 §3], and gives every
// other request a deadline.
//
// [RFC 6750 §3]: https://www.rfc-editor.org/rfc/rfc6750.html#section-3
func Guard(bearer, realm string, timeout time.Duration, deny func(http.ResponseWriter), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bearer == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+bearer)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
			deny(w)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func HasMediaType(r *http.Request, want string) bool {
	got, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && got == want
}

func Decode(body io.Reader, output any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func HTTPSURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" &&
		u.RawQuery == "" && !u.ForceQuery && len(value) <= 2048
}
