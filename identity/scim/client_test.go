package scim

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/holon-sh/protocol/identity"
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

func TestClientFindsAUser(t *testing.T) {
	backend := newFakeBackend()
	backend.users["u1"] = User{ID: "u1", UserName: `a"b@example.test`}
	client := serve(t, backend)
	if user, err := client.FindUser(t.Context(), `a"b@example.test`); err != nil || user.ID != "u1" {
		t.Fatalf("found %+v, %v", user, err)
	}
	if _, err := client.FindUser(t.Context(), "nobody@example.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nobody: %v", err)
	}
}

func TestClientMapsErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"invalid", ErrInvalid, ErrInvalid},
		{"not found", ErrNotFound, ErrNotFound},
		{"conflict", ErrConflict, ErrConflict},
		{"unavailable", errors.New("private provider failure"), ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := serve(t, failingBackend{test.err})
			ctx := t.Context()
			remove := Patch{Operations: []Operation{{Op: "remove", Path: "x"}}}
			_, capabilitiesErr := client.Capabilities(ctx)
			_, findErr := client.FindUser(ctx, "a")
			_, getErr := client.GetUser(ctx, "u1")
			_, createErr := client.CreateUser(ctx, User{UserName: "a"})
			_, listErr := client.ListUsers(ctx, 1, 1)
			_, groupsErr := client.ListGroups(ctx, 1, 1)
			_, createGroupErr := client.CreateGroup(ctx, identity.PermissionSet{Kind: "Session", UID: "one"})
			_, patchErr := client.PatchUser(ctx, "u1", remove)
			_, patchGroupErr := client.PatchGroup(ctx, "g1", remove)
			for name, err := range map[string]error{
				"capabilities": capabilitiesErr, "find": findErr, "get": getErr, "create": createErr, "list": listErr, "groups": groupsErr, "create group": createGroupErr,
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
