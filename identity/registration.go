package identity

import (
	"context"
	"errors"
	"slices"

	"github.com/holon-sh/protocol/oauthscope"

	"github.com/holon-sh/protocol/identity/internal/adapter"
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

// Spec is every resource server its owner, a Kind and UID, holds. Each of Audiences is a resource indicator as
// [RFC 8707 §2] defines it, and Scopes are the scope tokens in the [RFC 6749 §3.3] grammar that each of them holds.
//
// [RFC 8707 §2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
// [RFC 6749 §3.3]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
type Spec struct {
	Kind      string                   `json:"kind"`
	UID       string                   `json:"uid"`
	Audiences []string                 `json:"audiences,omitempty"`
	Bindings  map[string]PermissionSet `json:"bindings,omitempty"`
	Scopes    []string                 `json:"scopes,omitempty"`
}

type registration struct {
	Spec Spec `json:"resource"`
}

// Backend holds each owner's resource servers. Ensure leaves the owner holding exactly the audiences of its Spec,
// so a Spec with none removes them all.
type Backend interface {
	Ensure(context.Context, Spec) error
}

func (s Spec) Validate() error {
	insecure := slices.ContainsFunc(s.Audiences, func(audience string) bool { return !adapter.HTTPSURL(audience) })
	if (PermissionSet{Kind: s.Kind, UID: s.UID}).Validate() != nil || insecure || len(slices.Compact(slices.Sorted(slices.Values(s.Audiences)))) != len(s.Audiences) {
		return errors.New("resource kind, UID and unique HTTPS audiences are required")
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
