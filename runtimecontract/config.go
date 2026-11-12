package runtimecontract

import (
	"net/http"
	"slices"
)

// AppDiscoveryRequest reports a request the platform may make of an app without a caller context: the methods that
// describe what the app serves.
func AppDiscoveryRequest(method, path, mcpMethod string) bool {
	return method == http.MethodHead && path == "/" || method == http.MethodPost && path == "/mcp" &&
		slices.Contains([]string{"server/discover", "tools/list", "resources/list", "events/list"}, mcpMethod)
}
