package protocol_test

import (
	"testing"

	"github.com/holon-sh/protocol"
)

func TestRemoteHeaderContract(t *testing.T) {
	for _, name := range []string{"x-api-key", "Authorization", "x_api_key"} {
		if !protocol.ValidRemoteHeader(name) {
			t.Errorf("rejected %q", name)
		}
	}
	for _, name := range []string{"", "x api", "étag", "x-holon-tenant", "Mcp-Session-Id", "Content-Type", "cookie"} {
		if protocol.ValidRemoteHeader(name) {
			t.Errorf("accepted %q", name)
		}
	}
}
