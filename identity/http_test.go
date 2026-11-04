package identity_test

import (
	"cmp"
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/holon-sh/protocol/identity"
)

type backend func(identity.Spec) error

func (b backend) Ensure(_ context.Context, s identity.Spec) error {
	return b(s)
}

func (b backend) Delete(_ context.Context, s identity.Spec) error {
	return b(s)
}

func TestResourceLifecycleContract(t *testing.T) {
	spec := identity.Spec{
		Kind: "Session", UID: "owner", Audience: "https://session.example/mcp",
		Scopes: []string{"app:chat:read", "app:chat:write"},
	}
	for _, test := range []struct {
		name                             string
		backendErr, ensureErr, deleteErr error
		credential                       string
		wantCalls                        int32
	}{
		{name: "create", wantCalls: 2},
		{name: "ownership conflict", backendErr: identity.ErrOwnership, ensureErr: identity.ErrOwnership, deleteErr: identity.ErrOwnership, wantCalls: 2},
		{name: "unavailable", backendErr: errors.New("private provider failure"), ensureErr: identity.ErrUnavailable, deleteErr: identity.ErrUnavailable, wantCalls: 2},
		{name: "wrong credential", credential: "wrong", ensureErr: identity.ErrUnavailable, deleteErr: identity.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			handler := identity.NewHandler(backend(func(s identity.Spec) error {
				calls.Add(1)
				if !reflect.DeepEqual(s, spec) {
					t.Errorf("backend request=%+v", s)
				}
				return test.backendErr
			}), "secret")
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			client, err := identity.NewClient(server.URL, cmp.Or(test.credential, "secret"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Ensure(t.Context(), spec); !errors.Is(err, test.ensureErr) {
				t.Fatalf("ensure=%v", err)
			}
			if err := client.Delete(t.Context(), spec); !errors.Is(err, test.deleteErr) {
				t.Fatalf("delete=%v", err)
			}
			if got := calls.Load(); got != test.wantCalls {
				t.Fatalf("backend calls=%d, want %d", got, test.wantCalls)
			}
		})
	}
}
