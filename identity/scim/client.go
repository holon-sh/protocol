package scim

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/holon-sh/protocol/identity/internal/adapter"

	"github.com/holon-sh/protocol/identity"
)

const maxResponse = 4 << 20

// Client calls Handler from Holon's side and maps its responses back to the sentinel errors. An
// authentication failure or any other status is ErrUnavailable.
type Client struct {
	adapter *adapter.Client
}

// NewClient returns a Client for the adapter at endpoint, the base URL that /scim/v2 hangs from.
func NewClient(endpoint, bearer string, transport *http.Client) (*Client, error) {
	client, err := adapter.NewClient(endpoint, bearer, transport, requestTimeout)
	if err != nil {
		return nil, err
	}
	return &Client{adapter: client}, nil
}

// Capabilities reads Holon's extension of the document of [RFC 7644 §4].
//
// [RFC 7644 §4]: https://www.rfc-editor.org/rfc/rfc7644.html#section-4
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	var config serviceProviderConfig
	err := c.call(ctx, http.MethodGet, "/ServiceProviderConfig", nil, http.StatusOK, &config)
	return config.Holon, err
}

// ListUsers is [RFC 7644 §3.4.2]; start is 1-based.
//
// [RFC 7644 §3.4.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2
func (c *Client) ListUsers(ctx context.Context, start, count int) (Page[User], error) {
	return listResources[User](ctx, c, "/Users", url.Values{"startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(count)}})
}

// FindUser is the userName eq filter of [RFC 7644 §3.4.2.2]; userName is unique, so nobody is ErrNotFound.
//
// [RFC 7644 §3.4.2.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.2
func (c *Client) FindUser(ctx context.Context, userName string) (User, error) {
	literal, _ := json.Marshal(userName)
	page, err := listResources[User](ctx, c, "/Users", url.Values{"filter": {"userName eq " + string(literal)}, "count": {"1"}})
	if err != nil {
		return User{}, err
	}
	if len(page.Resources) == 0 {
		return User{}, ErrNotFound
	}
	return page.Resources[0], nil
}

// GetUser is [RFC 7644 §3.4.1].
//
// [RFC 7644 §3.4.1]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.1
func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	var user User
	err := c.call(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil, http.StatusOK, &user)
	return user, err
}

// CreateUser is [RFC 7644 §3.3].
//
// [RFC 7644 §3.3]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3
func (c *Client) CreateUser(ctx context.Context, user User) (User, error) {
	var created User
	err := c.call(ctx, http.MethodPost, "/Users", userResource{User: user, Schemas: []string{schemaUser}}, http.StatusCreated, &created)
	return created, err
}

// PatchUser is [RFC 7644 §3.5.2].
//
// [RFC 7644 §3.5.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2
func (c *Client) PatchUser(ctx context.Context, id string, patch Patch) (User, error) {
	var user User
	err := c.call(ctx, http.MethodPatch, "/Users/"+url.PathEscape(id), patchOp{Patch: patch, Schemas: []string{schemaPatchOp}}, http.StatusOK, &user)
	return user, err
}

// DeleteUser is [RFC 7644 §3.6].
//
// [RFC 7644 §3.6]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.6
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/Users/"+url.PathEscape(id), nil, http.StatusNoContent, nil)
}

// ListGroups is [RFC 7644 §3.4.2]; start is 1-based.
//
// [RFC 7644 §3.4.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2
func (c *Client) ListGroups(ctx context.Context, start, count int) (Page[Group], error) {
	return listResources[Group](ctx, c, "/Groups", url.Values{"startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(count)}})
}

// CreateGroup is [RFC 7644 §3.3].
//
// [RFC 7644 §3.3]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3
func (c *Client) CreateGroup(ctx context.Context, set identity.PermissionSet) (Group, error) {
	var created Group
	group := Group{ExternalID: set.Kind + "/" + set.UID}
	err := c.call(ctx, http.MethodPost, "/Groups", groupResource{Group: group, Schemas: []string{schemaGroup}}, http.StatusCreated, &created)
	return created, err
}

// PatchGroup is [RFC 7644 §3.5.2].
//
// [RFC 7644 §3.5.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2
func (c *Client) PatchGroup(ctx context.Context, id string, patch Patch) (Group, error) {
	var group Group
	err := c.call(ctx, http.MethodPatch, "/Groups/"+url.PathEscape(id), patchOp{Patch: patch, Schemas: []string{schemaPatchOp}}, http.StatusOK, &group)
	return group, err
}

func listResources[T any](ctx context.Context, c *Client, path string, query url.Values) (Page[T], error) {
	var page Page[T]
	err := c.call(ctx, http.MethodGet, path+"?"+query.Encode(), nil, http.StatusOK, &page)
	return page, err
}

func (c *Client) call(ctx context.Context, method, path string, request any, want int, output any) error {
	var body []byte
	if request != nil {
		data, err := json.Marshal(request)
		if err != nil {
			return ErrInvalid
		}
		body = data
	}
	response, err := c.adapter.Do(ctx, method, "/scim/v2"+path, mediaType, body)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	limited := io.LimitReader(response.Body, maxResponse)
	if response.StatusCode != want {
		return statusError(response.StatusCode)
	}
	if output != nil && json.NewDecoder(limited).Decode(output) != nil {
		return ErrUnavailable
	}
	return nil
}

func statusError(status int) error {
	switch status {
	case http.StatusBadRequest:
		return ErrInvalid
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	}
	return ErrUnavailable
}
