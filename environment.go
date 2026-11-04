package protocol

import "strings"

const RuntimeConfigEnv = "HOLON_MCP_RUNTIME_CONFIG"

func DependencyEnvName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_MCP_URL"
}
