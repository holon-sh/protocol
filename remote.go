package protocol

import (
	"cmp"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

func RemoteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.RawPath != "" {
		return nil, errors.New("remote endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	port, _ := strconv.ParseInt(cmp.Or(u.Port(), "443"), 10, 32)
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return nil, errors.New("remote endpoints require DNS hostnames")
	}
	if _, err = (Egress{{Host: u.Hostname(), Ports: []int32{int32(port)}}}).Normalize(); err != nil {
		return nil, err
	}
	return u, nil
}

// Endpoint expands the URL with lookup's input values and checks the result.
func (r Remote) Endpoint(lookup func(string) (string, bool)) (*url.URL, error) {
	raw, complete := Expand(r.URL, lookup)
	if !complete {
		return nil, errors.New("remote endpoint names an input without a value")
	}
	return RemoteURL(raw)
}

func ValidRemoteHeader(name string) bool {
	name = strings.ToLower(name)
	if !validHeaderFieldName(name) || slices.ContainsFunc(
		[]string{"x-holon-", "x-forwarded-", "x-envoy-", "x-b3-", "mcp-", "sec-"},
		func(prefix string) bool { return strings.HasPrefix(name, prefix) },
	) {
		return false
	}
	return !slices.Contains([]string{
		"host", "connection", "proxy-connection", "proxy-authorization",
		"proxy-authenticate", "cookie", "set-cookie", "forwarded",
		"origin", "referer", "content-length", "content-type",
		"accept", "accept-encoding", "transfer-encoding", "te",
		"trailer", "upgrade", "keep-alive", "baggage",
		"traceparent", "tracestate",
	}, name)
}

// Validate checks the remote against the app's inputs. A placeholder in the URL may stand for a DNS label or a path
// segment, so the URL must be valid with every declared input replaced by one.
func (r Remote) Validate(env map[string]Input) error {
	declared := func(name string) (string, bool) {
		_, ok := env[name]
		return "holon.invalid", ok
	}
	if _, err := r.Endpoint(declared); err != nil {
		return err
	}
	seen := map[string]bool{}
	for name, template := range r.Headers {
		canonical := http.CanonicalHeaderKey(name)
		if _, complete := Expand(template, declared); !ValidRemoteHeader(name) || seen[canonical] || !complete {
			return errors.New("invalid remote header binding")
		}
		if canonical == "Authorization" && !slices.ContainsFunc(TemplateInputs(template), func(name string) bool { return env[name].IsSecret }) {
			return errors.New("authorization header requires a secret reference")
		}
		seen[canonical] = true
	}
	return nil
}

// validHeaderFieldName reports whether name is an [RFC 9110 §5.6.2] token.
//
// [RFC 9110 §5.6.2]: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2
func validHeaderFieldName(name string) bool {
	return name != "" && !strings.ContainsFunc(name, func(r rune) bool {
		return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
	})
}
