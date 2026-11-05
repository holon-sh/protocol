package scim

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/holon-sh/protocol/identity"
)

var (
	ErrNotFound    = errors.New("scim resource not found")
	ErrFilter      = errors.New("scim filter not supported")
	ErrInvalid     = errors.New("scim request invalid")
	ErrConflict    = errors.New("scim resource conflict")
	ErrUnavailable = errors.New("scim backend unavailable")
)

// User is the core User resource of [RFC 7643 §4.1] limited to what Holon reads or writes, plus one Holon
// extension schema as [RFC 7643 §3.3] allows. Holon sets userName to the email address. Password is
// write-only and temporary; Groups is read-only.
//
// [RFC 7643 §4.1]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1
// [RFC 7643 §3.3]: https://www.rfc-editor.org/rfc/rfc7643.html#section-3.3
type User struct {
	ID         string         `json:"id"`                   // RFC 7643 §3.1
	ExternalID string         `json:"externalId,omitempty"` // RFC 7643 §3.1
	UserName   string         `json:"userName"`             // RFC 7643 §4.1.1
	Name       *Name          `json:"name,omitempty"`       // RFC 7643 §4.1.1
	Emails     []Email        `json:"emails,omitempty"`     // RFC 7643 §4.1.2
	Active     bool           `json:"active"`               // RFC 7643 §4.1.1
	Password   string         `json:"password,omitempty"`   // RFC 7643 §4.1.1
	Groups     []Ref          `json:"groups,omitempty"`     // RFC 7643 §4.1.2
	Holon      *UserExtension `json:"urn:holon:params:scim:schemas:extension:user:1.0,omitempty"`
	Meta       Meta           `json:"meta"` // RFC 7643 §3.1
}

// UserExtension is Holon's read-only extension to User: PendingSetup is true until the person has chosen
// their own password.
type UserExtension struct {
	PendingSetup bool `json:"pendingSetup"`
}

// Name is the name attribute of [RFC 7643 §4.1.1].
//
// [RFC 7643 §4.1.1]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1.1
type Name struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email is one value of the emails attribute of [RFC 7643 §4.1.2].
//
// [RFC 7643 §4.1.2]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1.2
type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

// Ref is a reference to another resource as in the groups attribute of [RFC 7643 §4.1.2] and the members
// attribute of [RFC 7643 §4.2]: Value is the referenced resource's id and Display its displayName.
//
// [RFC 7643 §4.1.2]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1.2
// [RFC 7643 §4.2]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.2
type Ref struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// Meta is the meta attribute of [RFC 7643 §3.1].
//
// [RFC 7643 §3.1]: https://www.rfc-editor.org/rfc/rfc7643.html#section-3.1
type Meta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitzero"`
	LastModified time.Time `json:"lastModified,omitzero"`
}

// Group is the core Group resource of [RFC 7643 §4.2]. Every Holon permission set is one Group: ExternalID
// is "<kind>/<uid>" and DisplayName is "<kind> <uid>", derived and read-only.
//
// [RFC 7643 §4.2]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.2
type Group struct {
	ID          string `json:"id"`
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Members     []Ref  `json:"members,omitempty"`
	Meta        Meta   `json:"meta"`
}

func (g Group) PermissionSet() (identity.PermissionSet, error) {
	i := strings.LastIndexByte(g.ExternalID, '/')
	if i < 0 {
		return identity.PermissionSet{}, ErrInvalid
	}
	set := identity.PermissionSet{Kind: g.ExternalID[:i], UID: g.ExternalID[i+1:]}
	if set.Validate() != nil {
		return identity.PermissionSet{}, ErrInvalid
	}
	return set, nil
}

// Filter is the subset of the [RFC 7644 §3.4.2.2] grammar Holon sends: userName eq "…", emails.value eq "…"
// or groups.value eq "<group id>", one at a time. Anything else is ErrFilter, which Handler answers with the
// invalidFilter scimType of [RFC 7644 §3.12].
//
// [RFC 7644 §3.4.2.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.2
// [RFC 7644 §3.12]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.12
type Filter struct {
	UserName string
	Email    string
	Group    string
}

// Page is the ListResponse of [RFC 7644 §3.4.2] with the index pagination of [RFC 7644 §3.4.2.4]: StartIndex is
// 1-based and Handler caps the requested count at 200. A Backend fills TotalResults and Resources, and Handler the
// rest.
//
// [RFC 7644 §3.4.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2
// [RFC 7644 §3.4.2.4]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.4
type Page[T any] struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
	Resources    []T `json:"Resources"`
}

// Patch is the PatchOp of [RFC 7644 §3.5.2]. Holon sends five shapes: replace active, replace name, replace
// password, add members and remove members[value eq "<user id>"].
//
// [RFC 7644 §3.5.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2
type Patch struct {
	Operations []Operation `json:"Operations"`
}

// Operation is one operation of [RFC 7644 §3.5.2]; Op is add, remove or replace.
//
// [RFC 7644 §3.5.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2
type Operation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ServiceProviderConfig is [RFC 7643 §5] plus Holon's capabilities extension. Handler sets Schemas, so a
// backend leaves it empty.
//
// [RFC 7643 §5]: https://www.rfc-editor.org/rfc/rfc7643.html#section-5
type ServiceProviderConfig struct {
	Schemas        []string     `json:"schemas"`
	Patch          Supported    `json:"patch"`
	Bulk           Supported    `json:"bulk"`
	Filter         Filtering    `json:"filter"`
	ChangePassword Supported    `json:"changePassword"`
	Sort           Supported    `json:"sort"`
	ETag           Supported    `json:"etag"`
	Holon          Capabilities `json:"urn:holon:params:scim:schemas:extension:capabilities:1.0"`
}

// Supported is a boolean capability of [RFC 7643 §5].
//
// [RFC 7643 §5]: https://www.rfc-editor.org/rfc/rfc7643.html#section-5
type Supported struct {
	Supported bool `json:"supported"`
}

// Filtering is the filter capability of [RFC 7643 §5].
//
// [RFC 7643 §5]: https://www.rfc-editor.org/rfc/rfc7643.html#section-5
type Filtering struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// Capabilities is read at request time: Invitations says the backend can send a setup message right now,
// Provider names the identity provider everyone signs in through when there is one.
type Capabilities struct {
	Invitations bool   `json:"invitations"`
	Provider    string `json:"provider,omitempty"`
}

// Backend serves the resources behind Handler. Ids are the backend's own. ListUsers and ListGroups receive a
// 1-based start index and a count of at most 200 ([RFC 7644 §3.4.2.4]). ListUsers answers ErrFilter to a Filter it
// cannot evaluate, and ListGroups only sees an empty Filter, because its fields are all User attributes;
// CreateUser is [RFC 7644 §3.3] and answers ErrConflict to a taken userName; CreateGroup is [RFC 7644 §3.3] and
// answers ErrConflict to a taken ExternalID and ErrInvalid to one that names no permission set; PatchUser and
// PatchGroup are [RFC 7644 §3.5.2] and answer ErrInvalid to an operation they do not implement; DeleteUser is
// [RFC 7644 §3.6]. An unknown id is ErrNotFound.
//
// [RFC 7644 §3.4.2.4]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.4
// [RFC 7644 §3.3]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3
// [RFC 7644 §3.5.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2
// [RFC 7644 §3.6]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.6
type Backend interface {
	Config(context.Context) (ServiceProviderConfig, error)
	ListUsers(context.Context, Filter, int, int) (Page[User], error)
	GetUser(context.Context, string) (User, error)
	CreateUser(context.Context, User) (User, error)
	PatchUser(context.Context, string, Patch) (User, error)
	DeleteUser(context.Context, string) error
	ListGroups(context.Context, Filter, int, int) (Page[Group], error)
	CreateGroup(context.Context, Group) (Group, error)
	PatchGroup(context.Context, string, Patch) (Group, error)
}
