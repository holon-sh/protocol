package runtimecontract

import (
	"net/http"
	"slices"
)

type Config struct {
	Version int               `json:"version"`
	Peers   map[string]string `json:"peers"`
	Callers []string          `json:"callers"`
}

func AppDiscoveryRequest(method, path, mcpMethod string) bool {
	return method == http.MethodHead && path == "/" || method == http.MethodPost && path == "/mcp" &&
		slices.Contains([]string{"server/discover", "tools/list"}, mcpMethod)
}
