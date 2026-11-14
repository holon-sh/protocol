package runtimecontract

//go:generate go run ./internal/generate ../spec/runtime

// The variables the platform sets in an app's container, besides protocol.PlatformEnv, each dependency's
// protocol.DependencyEnvName, and the OpenTelemetry variables protocol names. The platform sets PlatformEnv to
// PlatformEnabled. An SDK sends DependencyTokenEnvSuffix's variable, which the platform does not set, as the bearer
// token of its calls to that dependency.
const (
	PlatformEnabled          = "1"
	HostEnv                  = "HOST"
	PortEnv                  = "PORT"
	DependencyTokenEnvSuffix = "_MCP_TOKEN"
)

// The waypoint sets these on a request to an app of the session from the session's audience.
const (
	ForwardedHostHeader  = "X-Forwarded-Host"
	ForwardedProtoHeader = "X-Forwarded-Proto"
)
