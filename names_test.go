package protocol_test

import (
	"testing"

	"github.com/holon-sh/protocol"
)

func TestValidAppNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		valid bool
	}{
		{"none", nil, true},
		{"unique", []string{"alpha", "beta"}, true},
		{"duplicate", []string{"alpha", "alpha"}, false},
		{"reserved", []string{"alpha", "mcp"}, false},
	} {
		if protocol.ValidAppNames(tc.names) != tc.valid {
			t.Errorf("%s: ValidAppNames(%q) = %v", tc.name, tc.names, !tc.valid)
		}
	}
}
