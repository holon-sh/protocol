package protocol_test

import (
	"strings"
	"testing"

	"github.com/holon-sh/protocol"
)

func TestSessionNameContract(t *testing.T) {
	for _, name := range []string{"cli-pr-42", strings.Repeat("a", 63)} {
		if !protocol.ValidSessionName(name) {
			t.Errorf("rejected %q", name)
		}
	}
	for _, name := range []string{"Cli-pr-42", strings.Repeat("a", 64), "dev", "admin", "production"} {
		if protocol.ValidSessionName(name) {
			t.Errorf("accepted %q", name)
		}
	}
}
