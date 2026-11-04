package identity

import (
	"context"
	"errors"
	"net/url"
	"slices"

	"github.com/holon-sh/protocol/oauthscope"
)

var (
	ErrOwnership   = errors.New("resource registration ownership conflict")
	ErrUnavailable = errors.New("resource registration unavailable")
)

type PermissionSet struct {
	Kind string `json:"kind"`
	UID  string `json:"uid"`
}

func (s PermissionSet) Validate() error {
	if s.Kind == "" || s.UID == "" || len(s.Kind) > 256 || len(s.UID) > 256 {
		return errors.New("permission set kind and UID are required")
	}
	return nil
}

// Spec is one resource server to register. Audience is a resource indicator as [RFC 8707 §2] defines it, and Scopes
// are scope tokens in the [RFC 6749 §3.3] grammar.
//
// [RFC 8707 §2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
// [RFC 6749 §3.3]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
type Spec struct {
	Kind     string                   `json:"kind"`
	UID      string                   `json:"uid"`
	Audience string                   `json:"audience"`
	Bindings map[string]PermissionSet `json:"bindings,omitempty"`
	Scopes   []string                 `json:"scopes,omitempty"`
}

type Request struct {
	Spec Spec `json:"resource"`
}

type Backend interface {
	Ensure(context.Context, Spec) error
	Delete(context.Context, Spec) error
}

func (s Spec) Validate() error {
	if (PermissionSet{Kind: s.Kind, UID: s.UID}).Validate() != nil || !httpsURL(s.Audience) {
		return errors.New("resource kind, UID and HTTPS audience are required")
	}
	for scope, set := range s.Bindings {
		if !slices.Contains(s.Scopes, scope) || set.Validate() != nil {
			return errors.New("bindings must reference declared scopes and valid permission sets")
		}
	}
	if !oauthscope.ValidScopes(s.Scopes) {
		return errors.New("resource scopes must be unique OAuth scope tokens of at most 256 bytes")
	}
	return nil
}

func httpsURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" &&
		u.RawQuery == "" && !u.ForceQuery && len(value) <= 2048
}
