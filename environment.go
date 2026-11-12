package protocol

import "strings"

// PlatformEnv is set to "1" by the controller in every app container. Requests reach such a container only through
// Holon's waypoint, which verifies X-Holon-Context and replaces any X-Holon-* header a client sent, so an app may trust
// those headers exactly when it is set.
const PlatformEnv = "HOLON_PLATFORM"

// DependencyEnvSuffix ends the name of the variable that holds a dependency's endpoint.
const DependencyEnvSuffix = "_MCP_URL"

func DependencyEnvName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + DependencyEnvSuffix
}
