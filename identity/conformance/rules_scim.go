package conformance

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/holon-sh/protocol/identity/scim"
)

const (
	serviceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	capabilitiesSchema          = "urn:holon:params:scim:schemas:extension:capabilities:1.0"
	scimMediaType               = "application/scim+json"
	maxCount                    = 200
)

var personName = scim.Name{GivenName: "Conformance", FamilyName: "Test"}

func uniqueEmail() string {
	return "conformance-" + strings.ToLower(rand.Text()) + "@example.test"
}

func temporaryPassword() string {
	return "Conformance-1-" + rand.Text()
}

func (s *suite) createPerson(ctx context.Context, password string) (scim.User, error) {
	email := uniqueEmail()
	created, err := s.users.CreateUser(ctx, scim.User{
		UserName: email, Emails: []scim.Email{{Value: email, Primary: true}}, Active: true, Password: password,
	})
	if err != nil {
		return scim.User{}, fmt.Errorf("create %s: %w", email, err)
	}
	return created, nil
}

func (s *suite) deleteUser(ctx context.Context, id string) {
	_ = s.users.DeleteUser(ctx, id)
}

func (s *suite) permissionGroup(ctx context.Context) (scim.Group, error) {
	groups, err := s.users.ListGroups(ctx, scim.Filter{}, 1, 1)
	if err != nil {
		return scim.Group{}, fmt.Errorf("list groups: %w", err)
	}
	if len(groups.Resources) != 1 {
		return scim.Group{}, errors.New("no permission-set group exists: register Config.Resource with a binding")
	}
	return groups.Resources[0], nil
}

// replaceOperation, addMember and removeMember build the shapes of [RFC 7644 §3.5.2] that Holon sends.
//
// [RFC 7644 §3.5.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2
func replaceOperation(path string, value any) scim.Patch {
	data, _ := json.Marshal(value)
	return scim.Patch{Operations: []scim.Operation{{Op: "replace", Path: path, Value: data}}}
}

func addMember(userID string) scim.Patch {
	data, _ := json.Marshal([]scim.Ref{{Value: userID}})
	return scim.Patch{Operations: []scim.Operation{{Op: "add", Path: "members", Value: data}}}
}

func removeMember(userID string) scim.Patch {
	literal, _ := json.Marshal(userID)
	return scim.Patch{Operations: []scim.Operation{{Op: "remove", Path: "members[value eq " + string(literal) + "]"}}}
}

func wantError(action string, err, want error) error {
	switch {
	case errors.Is(err, want):
		return nil
	case err == nil:
		return fmt.Errorf("%s succeeded, want %w", action, want)
	}
	return fmt.Errorf("%s: %w, want %w", action, err, want)
}

func holdsRef(refs []scim.Ref, value string) bool {
	return slices.ContainsFunc(refs, func(ref scim.Ref) bool { return ref.Value == value })
}

func (s *suite) checkSCIMConfig(ctx context.Context) error {
	config, err := s.users.Config(ctx)
	if err != nil {
		return err
	}
	return validateConfig(config)
}

// validateConfig holds the document of [RFC 7643 §5] to what Holon relies on.
//
// [RFC 7643 §5]: https://www.rfc-editor.org/rfc/rfc7643.html#section-5
func validateConfig(config scim.ServiceProviderConfig) error {
	switch {
	case !slices.Contains(config.Schemas, serviceProviderConfigSchema) || !slices.Contains(config.Schemas, capabilitiesSchema):
		return fmt.Errorf("schemas %q", config.Schemas)
	case !config.Patch.Supported:
		return errors.New("patch is not supported")
	case !config.Filter.Supported:
		return errors.New("filter is not supported")
	case config.Filter.MaxResults < 1 || config.Filter.MaxResults > maxCount:
		return fmt.Errorf("filter.maxResults %d is not in 1..%d", config.Filter.MaxResults, maxCount)
	case config.Bulk.Supported || config.Sort.Supported:
		return errors.New("bulk and sort are advertised but the SCIM subset does not serve them")
	}
	return nil
}

func (s *suite) checkSCIMList(ctx context.Context) error {
	for range 2 {
		person, err := s.createPerson(ctx, temporaryPassword())
		if err != nil {
			return err
		}
		defer s.deleteUser(ctx, person.ID)
	}
	first, err := s.users.ListUsers(ctx, scim.Filter{}, 1, 1)
	if err != nil {
		return fmt.Errorf("first page: %w", err)
	}
	if first.TotalResults < 2 || first.StartIndex != 1 || first.ItemsPerPage != 1 || len(first.Resources) != 1 {
		return fmt.Errorf("first page of one: %+v", first)
	}
	second, err := s.users.ListUsers(ctx, scim.Filter{}, 2, 1)
	if err != nil {
		return fmt.Errorf("second page: %w", err)
	}
	if second.StartIndex != 2 || len(second.Resources) != 1 || second.Resources[0].ID == first.Resources[0].ID {
		return fmt.Errorf("second page of one: %+v after %+v", second, first)
	}
	total, err := s.users.ListUsers(ctx, scim.Filter{}, 1, 0)
	if err != nil {
		return fmt.Errorf("count 0: %w", err)
	}
	if total.TotalResults < 2 || len(total.Resources) != 0 {
		return fmt.Errorf("count 0 must report only the total: %+v", total)
	}
	capped, err := s.users.ListUsers(ctx, scim.Filter{}, 1, maxCount+1)
	if err != nil {
		return fmt.Errorf("count above the cap: %w", err)
	}
	if len(capped.Resources) > maxCount || capped.ItemsPerPage > maxCount {
		return fmt.Errorf("count above the cap returned %d resources", len(capped.Resources))
	}
	return nil
}

func (s *suite) checkSCIMListGroups(ctx context.Context) error {
	person, err := s.createPerson(ctx, temporaryPassword())
	if err != nil {
		return err
	}
	defer s.deleteUser(ctx, person.ID)
	group, err := s.permissionGroup(ctx)
	if err != nil {
		return err
	}
	if _, err := s.users.PatchGroup(ctx, group.ID, addMember(person.ID)); err != nil {
		return fmt.Errorf("add members: %w", err)
	}
	defer func() { _, _ = s.users.PatchGroup(ctx, group.ID, removeMember(person.ID)) }()
	for start := 1; ; start += maxCount {
		page, err := s.users.ListUsers(ctx, scim.Filter{}, start, maxCount)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		if i := slices.IndexFunc(page.Resources, func(user scim.User) bool { return user.ID == person.ID }); i >= 0 {
			if !holdsRef(page.Resources[i].Groups, group.ID) {
				return fmt.Errorf("the list answers groups %+v for a member of %s", page.Resources[i].Groups, group.ID)
			}
			return nil
		}
		if start+maxCount > page.TotalResults {
			return fmt.Errorf("the list does not include %s", person.ID)
		}
	}
}

func (s *suite) checkSCIMCreateGroup(ctx context.Context) error {
	kind, uid := "Conformance", strings.ToLower(rand.Text())
	created, err := s.users.CreateGroup(ctx, scim.Group{ExternalID: kind + "/" + uid})
	if err != nil {
		return fmt.Errorf("create group: %w", err)
	}
	if created.ID == "" || created.ExternalID != kind+"/"+uid || created.DisplayName != kind+" "+uid || len(created.Members) != 0 {
		return fmt.Errorf("created %+v", created)
	}
	_, err = s.users.CreateGroup(ctx, scim.Group{ExternalID: created.ExternalID})
	if err := wantError("a second create of one externalId", err, scim.ErrConflict); err != nil {
		return err
	}
	for start := 1; ; start += maxCount {
		page, err := s.users.ListGroups(ctx, scim.Filter{}, start, maxCount)
		if err != nil {
			return fmt.Errorf("list groups: %w", err)
		}
		if slices.ContainsFunc(page.Resources, func(group scim.Group) bool { return group.ID == created.ID }) {
			break
		}
		if start+maxCount > page.TotalResults {
			return fmt.Errorf("the list does not include the created group %s", created.ID)
		}
	}
	_, err = s.users.CreateGroup(ctx, scim.Group{ExternalID: kind})
	return wantError("an externalId without a uid", err, scim.ErrInvalid)
}

func (s *suite) wantOnly(ctx context.Context, filter scim.Filter, id string) error {
	page, err := s.users.ListUsers(ctx, filter, 1, maxCount)
	if err != nil {
		return fmt.Errorf("filter %+v: %w", filter, err)
	}
	if page.TotalResults != 1 || len(page.Resources) != 1 || page.Resources[0].ID != id {
		return fmt.Errorf("filter %+v matched %d resources, want only %s", filter, page.TotalResults, id)
	}
	return nil
}

func (s *suite) checkSCIMFilter(ctx context.Context) error {
	person, err := s.createPerson(ctx, temporaryPassword())
	if err != nil {
		return err
	}
	defer s.deleteUser(ctx, person.ID)
	if err := s.wantOnly(ctx, scim.Filter{UserName: person.UserName}, person.ID); err != nil {
		return err
	}
	if err := s.wantOnly(ctx, scim.Filter{Email: person.UserName}, person.ID); err != nil {
		return err
	}
	none, err := s.users.ListUsers(ctx, scim.Filter{UserName: uniqueEmail()}, 1, maxCount)
	if err != nil {
		return err
	}
	if none.TotalResults != 0 || len(none.Resources) != 0 {
		return fmt.Errorf("a filter matching nobody returned %d resources", none.TotalResults)
	}
	group, err := s.permissionGroup(ctx)
	if err != nil {
		return err
	}
	if _, err := s.users.PatchGroup(ctx, group.ID, addMember(person.ID)); err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	defer func() { _, _ = s.users.PatchGroup(ctx, group.ID, removeMember(person.ID)) }()
	members, err := s.users.ListUsers(ctx, scim.Filter{Group: group.ID}, 1, maxCount)
	if err != nil {
		return fmt.Errorf("groups.value filter: %w", err)
	}
	if !slices.ContainsFunc(members.Resources, func(user scim.User) bool { return user.ID == person.ID }) {
		return fmt.Errorf("groups.value eq %q did not return the member", group.ID)
	}
	return s.wantInvalidFilter(ctx)
}

// wantInvalidFilter sends a filter outside the subset and expects the error of [RFC 7644 §3.12].
//
// [RFC 7644 §3.12]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.12
func (s *suite) wantInvalidFilter(ctx context.Context) error {
	response, err := s.adapter.Do(ctx, http.MethodGet, "/scim/v2/Users?"+url.Values{"filter": {`displayName eq "x"`}}.Encode(), scimMediaType, nil)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	var body struct {
		ScimType string `json:"scimType"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponse)).Decode(&body); err != nil {
		return fmt.Errorf("error body: %w", err)
	}
	if response.StatusCode != http.StatusBadRequest || body.ScimType != "invalidFilter" || response.Header.Get("Content-Type") != scimMediaType {
		return fmt.Errorf("unsupported filter: status %d, scimType %q, content type %q", response.StatusCode, body.ScimType, response.Header.Get("Content-Type"))
	}
	return nil
}

func (s *suite) checkSCIMCreate(ctx context.Context) error {
	created, err := s.createPerson(ctx, temporaryPassword())
	if err != nil {
		return err
	}
	defer s.deleteUser(ctx, created.ID)
	if created.ID == "" || !created.Active {
		return fmt.Errorf("created %+v", created)
	}
	fetched, err := s.users.GetUser(ctx, created.ID)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	for name, user := range map[string]scim.User{"create": created, "get": fetched} {
		if user.Password != "" {
			return fmt.Errorf("%s returned the password", name)
		}
		if user.Holon == nil || !user.Holon.PendingSetup {
			return fmt.Errorf("%s: a person with a temporary password must be pendingSetup: %+v", name, user.Holon)
		}
	}
	if fetched.UserName != created.UserName || fetched.ID != created.ID {
		return fmt.Errorf("get %+v after create %+v", fetched, created)
	}
	_, err = s.users.CreateUser(ctx, scim.User{UserName: created.UserName, Active: true})
	return wantError("a second user with one userName", err, scim.ErrConflict)
}

func (s *suite) checkSCIMPatch(ctx context.Context) error {
	person, err := s.createPerson(ctx, temporaryPassword())
	if err != nil {
		return err
	}
	defer s.deleteUser(ctx, person.ID)
	deactivated, err := s.users.PatchUser(ctx, person.ID, replaceOperation("active", false))
	if err != nil {
		return fmt.Errorf("replace active: %w", err)
	}
	if deactivated.Active {
		return errors.New("replace active left the user active")
	}
	named, err := s.users.PatchUser(ctx, person.ID, replaceOperation("name", personName))
	if err != nil {
		return fmt.Errorf("replace name: %w", err)
	}
	if named.Name == nil || *named.Name != personName {
		return fmt.Errorf("replace name returned %+v", named.Name)
	}
	changed, err := s.users.PatchUser(ctx, person.ID, replaceOperation("password", temporaryPassword()))
	if err != nil {
		return fmt.Errorf("replace password: %w", err)
	}
	if changed.Password != "" {
		return errors.New("replace password returned the password")
	}
	if changed.Holon == nil || !changed.Holon.PendingSetup {
		return errors.New("a password written through SCIM is temporary, but the user is not pendingSetup")
	}
	group, err := s.permissionGroup(ctx)
	if err != nil {
		return err
	}
	if _, err := s.users.PatchGroup(ctx, group.ID, addMember(person.ID)); err != nil {
		return fmt.Errorf("add members: %w", err)
	}
	defer func() { _, _ = s.users.PatchGroup(ctx, group.ID, removeMember(person.ID)) }()
	if err := s.wantMembership(ctx, person.ID, group.ID, true); err != nil {
		return err
	}
	if _, err := s.users.PatchGroup(ctx, group.ID, removeMember(person.ID)); err != nil {
		return fmt.Errorf("remove members: %w", err)
	}
	return s.wantMembership(ctx, person.ID, group.ID, false)
}

func (s *suite) wantMembership(ctx context.Context, userID, groupID string, want bool) error {
	user, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if holdsRef(user.Groups, groupID) != want {
		return fmt.Errorf("membership of %s in the user's groups %+v, want %v", groupID, user.Groups, want)
	}
	return nil
}

func (s *suite) checkSCIMDelete(ctx context.Context) error {
	person, err := s.createPerson(ctx, temporaryPassword())
	if err != nil {
		return err
	}
	defer s.deleteUser(ctx, person.ID)
	if err := s.users.DeleteUser(ctx, person.ID); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	_, err = s.users.GetUser(ctx, person.ID)
	if err := wantError("get after delete", err, scim.ErrNotFound); err != nil {
		return err
	}
	return wantError("second delete", s.users.DeleteUser(ctx, person.ID), scim.ErrNotFound)
}
