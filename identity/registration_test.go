package identity_test

import (
	"testing"

	"github.com/holon-sh/protocol/identity"
)

func TestValidateRejectsDuplicates(t *testing.T) {
	for name, spec := range map[string]identity.Spec{
		"scopes":    {Kind: "Session", UID: "owner", Scopes: []string{"read", "read"}},
		"audiences": {Kind: "Session", UID: "owner", Audiences: []string{"https://session.example/mcp", "https://session.example/mcp"}},
	} {
		if err := spec.Validate(); err == nil {
			t.Errorf("Validate() accepted duplicate %s", name)
		}
	}
}
