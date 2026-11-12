package runtimecontract

import (
	"net/http"
	"slices"
)

// CatalogMethods are the MCP methods that list what a server serves, which types are generated from.
var CatalogMethods = []string{"tools/list", "resources/list", "events/list"}

// AppDiscoveryRequest reports a request the platform may make of an app without a caller context: the methods that
// describe what the app serves.
func AppDiscoveryRequest(method, path, mcpMethod string) bool {
	return method == http.MethodHead && path == "/" || method == http.MethodPost && path == "/mcp" &&
		(mcpMethod == "server/discover" || slices.Contains(CatalogMethods, mcpMethod))
}
