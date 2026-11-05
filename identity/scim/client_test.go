package scim

import (
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestClientReachesAnIDWithReservedCharacters(t *testing.T) {
	backend := newFakeBackend()
	backend.users["a/b c"] = User{ID: "a/b c"}
	user, err := serve(t, backend).GetUser(t.Context(), "a/b c")
	if err != nil || user.ID != "a/b c" {
		t.Fatalf("get %+v, %v", user, err)
	}
}

func TestClientFilters(t *testing.T) {
	t.Run("userName with a quote", func(t *testing.T) {
		backend := newFakeBackend()
		filter := Filter{UserName: `a"b@example.test`}
		if _, err := serve(t, backend).ListUsers(t.Context(), filter, 1, 50); err != nil {
			t.Fatal(err)
		}
		if backend.filter != filter {
			t.Fatalf("backend filter %+v", backend.filter)
		}
	})
	t.Run("two terms are not sent", func(t *testing.T) {
		_, err := serve(t, failingBackend{errors.New("backend reached")}).ListUsers(t.Context(), Filter{UserName: "a", Group: "b"}, 1, 1)
		if !errors.Is(err, ErrFilter) {
			t.Fatalf("list: %v", err)
		}
	})
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
			_, createGroupErr := client.CreateGroup(ctx, Group{ExternalID: "Session/one"})
			_, patchErr := client.PatchUser(ctx, "u1", remove)
			_, patchGroupErr := client.PatchGroup(ctx, "g1", remove)
			for name, err := range map[string]error{
				"config": configErr, "get": getErr, "create": createErr, "list": listErr, "groups": groupsErr, "create group": createGroupErr,
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
