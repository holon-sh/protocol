package identity_test

import (
	"testing"

	"github.com/holon-sh/protocol/identity"
)

func TestValidateRejectsInvalidScopes(t *testing.T) {
	spec := identity.Spec{Kind: "Session", UID: "owner", Audience: "https://session.example/mcp", Scopes: []string{"read"}}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.Scopes = []string{"read", "read"}
	if err := spec.Validate(); err == nil {
		t.Fatal("Validate() accepted duplicate scopes")
	}
}
