package protocol_test

import (
	"testing"

	"github.com/holon-sh/protocol"
)

func TestValidEnvNameReservesThePlatformsVariables(t *testing.T) {
	for _, name := range []string{"API_KEY", "MCP_URL", "PEER_MCP_URL_SUFFIX", "PEER_MCP_TOKEN"} {
		if !protocol.ValidEnvName(name) {
			t.Errorf("ValidEnvName(%q) = false", name)
		}
	}
	for _, name := range []string{protocol.PlatformEnv, "HOLON_ANYTHING", protocol.DependencyEnvName("peer"), "ANY_MCP_URL", protocol.OTELServiceNameEnv} {
		if protocol.ValidEnvName(name) {
			t.Errorf("ValidEnvName(%q) = true", name)
		}
	}
}
