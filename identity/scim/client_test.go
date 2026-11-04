package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func serve(t *testing.T, backend Backend) *Client {
	t.Helper()
	server := httptest.NewTLSServer(Handler(backend, bearer))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL+"/", bearer, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func raw(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func TestClientUserLifecycle(t *testing.T) {
	backend := newFakeBackend()
	client := serve(t, backend)
	ctx := t.Context()
	created, err := client.CreateUser(ctx, User{
		UserName: "a@example.test", Active: true, Password: "temporary",
		Emails: []Email{{Value: "a@example.test", Primary: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "u1" || created.Password != "" || created.Holon == nil || !created.Holon.PendingSetup || created.Meta.ResourceType != "User" {
		t.Fatalf("created %+v", created)
	}
	if backend.users["u1"].Password != "temporary" {
		t.Fatalf("backend password %q", backend.users["u1"].Password)
	}
	got, err := client.GetUser(ctx, "u1")
	if err != nil || !reflect.DeepEqual(got, created) {
		t.Fatalf("get %+v, %v; want %+v", got, err, created)
	}
	if err := client.DeleteUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetUser(ctx, "u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestClientReachesAnIDWithReservedCharacters(t *testing.T) {
	backend := newFakeBackend()
	backend.users["a/b c"] = User{ID: "a/b c"}
	user, err := serve(t, backend).GetUser(t.Context(), "a/b c")
	if err != nil || user.ID != "a/b c" {
		t.Fatalf("get %+v, %v", user, err)
	}
}

func TestClientFilters(t *testing.T) {
	backend := newFakeBackend()
	client := serve(t, backend)
	for _, test := range []struct {
		name   string
		filter Filter
	}{
		{"none", Filter{}},
		{"userName with a quote", Filter{UserName: `a"b@example.test`}},
		{"emails.value", Filter{Email: "a@example.test"}},
		{"groups.value", Filter{Group: "g1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.ListUsers(t.Context(), test.filter, 1, 50); err != nil {
				t.Fatal(err)
			}
			if backend.filter != test.filter {
				t.Fatalf("backend filter %+v", backend.filter)
			}
		})
	}
	t.Run("two terms are not sent", func(t *testing.T) {
		_, err := serve(t, failingBackend{errors.New("backend reached")}).ListUsers(t.Context(), Filter{UserName: "a", Group: "b"}, 1, 1)
		if !errors.Is(err, ErrFilter) {
			t.Fatalf("list: %v", err)
		}
	})
}

func TestClientReadsAPage(t *testing.T) {
	backend := newFakeBackend()
	backend.users = map[string]User{"u1": {ID: "u1"}, "u2": {ID: "u2"}, "u3": {ID: "u3"}}
	client := serve(t, backend)
	users, err := client.ListUsers(t.Context(), Filter{}, 2, 1)
	if err != nil || users.TotalResults != 3 || users.StartIndex != 2 || users.ItemsPerPage != 1 || len(users.Resources) != 1 || users.Resources[0].ID != "u2" {
		t.Fatalf("users %+v, %v", users, err)
	}
	groups, err := client.ListGroups(t.Context(), Filter{}, 2, 1)
	if err != nil || groups.TotalResults != 2 || groups.StartIndex != 2 || len(groups.Resources) != 1 || groups.Resources[0].ID != "g2" {
		t.Fatalf("groups %+v, %v", groups, err)
	}
}

func TestPatchShapes(t *testing.T) {
	for _, test := range []struct {
		name      string
		group     bool
		operation Operation
	}{
		{name: "replace active", operation: Operation{Op: "replace", Path: "active", Value: raw(false)}},
		{name: "replace name", operation: Operation{Op: "replace", Path: "name", Value: raw(Name{GivenName: "Ada", FamilyName: "Lovelace"})}},
		{name: "replace password", operation: Operation{Op: "replace", Path: "password", Value: raw("second")}},
		{name: "add members", group: true, operation: Operation{Op: "add", Path: "members", Value: raw([]Ref{{Value: "u1"}})}},
		{name: "remove members", group: true, operation: Operation{Op: "remove", Path: `members[value eq "u1"]`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeBackend()
			client := serve(t, backend)
			patch := Patch{Operations: []Operation{test.operation}}
			var err error
			if test.group {
				_, err = client.PatchGroup(t.Context(), "g1", patch)
			} else {
				_, err = client.PatchUser(t.Context(), "u1", patch)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(backend.operations, patch.Operations) {
				t.Fatalf("backend saw %+v, want %+v", backend.operations, patch.Operations)
			}
		})
	}
}

func TestClientMapsErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"filter", ErrFilter, ErrFilter},
		{"invalid", ErrInvalid, ErrInvalid},
		{"not found", ErrNotFound, ErrNotFound},
		{"conflict", ErrConflict, ErrConflict},
		{"unavailable", errors.New("private provider failure"), ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := serve(t, failingBackend{test.err})
			ctx := t.Context()
			remove := Patch{Operations: []Operation{{Op: "remove", Path: "x"}}}
			_, configErr := client.Config(ctx)
			_, getErr := client.GetUser(ctx, "u1")
			_, createErr := client.CreateUser(ctx, User{UserName: "a"})
			_, listErr := client.ListUsers(ctx, Filter{}, 1, 1)
			_, groupsErr := client.ListGroups(ctx, Filter{}, 1, 1)
			_, patchErr := client.PatchUser(ctx, "u1", remove)
			_, patchGroupErr := client.PatchGroup(ctx, "g1", remove)
			for name, err := range map[string]error{
				"config": configErr, "get": getErr, "create": createErr, "list": listErr, "groups": groupsErr,
				"patch": patchErr, "patch group": patchGroupErr, "delete": client.DeleteUser(ctx, "u1"),
			} {
				if !errors.Is(err, test.want) {
					t.Errorf("%s: %v, want %v", name, err, test.want)
				}
			}
		})
	}
	t.Run("a malformed body is unavailable", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }))
		defer server.Close()
		client, err := NewClient(server.URL, bearer, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.GetUser(t.Context(), "u1"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("get: %v", err)
		}
	})
}
