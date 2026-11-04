package protocol

import (
	"slices"
	"strings"
)

const (
	ModeDevelopment = "development"
	ModeProduction  = "production"
	ProductionName  = "production"
)

const PlatformPaths = `/connections
/mcp
/v2
/registry
/.well-known
/me
/upload-grants
/values
/config
/sessions
/platform
/egress
/identity
/mcpb
/v0.1
`

func ReservedAppNames() []string {
	names := []string{"api", "default", "auth"}
	for _, path := range strings.Fields(PlatformPaths) {
		names = append(names, strings.TrimPrefix(path, "/"))
	}
	return names
}

func ValidAppName(value string) bool {
	return len(value) <= 49 && ValidDNSLabel(value) && !slices.Contains(ReservedAppNames(), value)
}

func ValidAppNames(names []string) bool {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] || !ValidAppName(name) {
			return false
		}
		seen[name] = true
	}
	return len(names) != 0
}
