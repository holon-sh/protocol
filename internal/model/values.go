// Package model holds the rules of the control contract and the artifact formats, from which spec/control and
// spec/artifact are written. The protocol package reads its patterns, bounds and reserved values from here, so that
// each is stated once.
package model

import (
	"maps"
	"slices"
	"strings"

	"github.com/holon-sh/protocol/internal/rule"
)

// DNSLabelPattern is Kubernetes' lowercase [RFC 1123 §2.1] hostname-label profile, without anchors.
//
// [RFC 1123 §2.1]: https://www.rfc-editor.org/rfc/rfc1123.html#section-2.1
const DNSLabelPattern = `[a-z0-9]([-a-z0-9]*[a-z0-9])?`

const (
	MaxDNSLabelBytes = 63
	MaxAppNameBytes  = 49
)

// PlatformPaths are the paths the platform serves on every host. Their first segments are reserved app names.
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

// ReservedAppNames are the names no app may take.
var ReservedAppNames = slices.Concat([]string{"api", "default", "auth"}, platformSegments())

func platformSegments() []string {
	var segments []string
	for _, path := range strings.Fields(PlatformPaths) {
		segments = append(segments, strings.TrimPrefix(path, "/"))
	}
	return segments
}

// EnvNamePattern is the syntax of a variable an app declares.
const EnvNamePattern = `^[A-Za-z_][A-Za-z0-9_]*$`

const (
	MaxEnvNameBytes = 128
	// MaxEnvEntries bounds an app's env, envTemplates, applied and supplied.
	MaxEnvEntries = 64
	// ReservedEnvPrefix begins every variable the controller owns.
	ReservedEnvPrefix = "HOLON_"
	// DependencyEnvSuffix ends the name of the variable that holds a dependency's endpoint.
	DependencyEnvSuffix = "_MCP_URL"
)

const (
	OTELServiceNameEnv          = "OTEL_SERVICE_NAME"
	OTELResourceAttributesEnv   = "OTEL_RESOURCE_ATTRIBUTES"
	OTELExporterOTLPEndpointEnv = "OTEL_EXPORTER_OTLP_ENDPOINT"
	OTELExporterOTLPProtocolEnv = "OTEL_EXPORTER_OTLP_PROTOCOL"
)

// ReservedEnv are the OpenTelemetry variables the controller sets in app containers, which carry the session key.
var ReservedEnv = []string{OTELServiceNameEnv, OTELResourceAttributesEnv, OTELExporterOTLPEndpointEnv, OTELExporterOTLPProtocolEnv}

// ScopePattern is an [RFC 6749 §3.3] scope-token.
//
// [RFC 6749 §3.3]: https://www.rfc-editor.org/rfc/rfc6749#section-3.3
const ScopePattern = `^[\x21\x23-\x5B\x5D-\x7E]+$`

const MaxScopeBytes = 256

// SHA256Digest is an [OCI image spec] SHA-256 digest, without anchors.
//
// [OCI image spec]: https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md#sha-256
const SHA256Digest = `sha256:[a-f0-9]{64}`

// RepositoryName is the [OCI distribution spec] <name> grammar.
//
// [OCI distribution spec]: https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests
const RepositoryName = `[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*`

// Tag is the [OCI distribution spec] <reference> grammar for a tag.
//
// [OCI distribution spec]: https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests
const Tag = `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`

// RegistryHost is an [RFC 1123 §2.1] host name or an [RFC 3986 §3.2.2] IP-literal, with an optional port.
//
// [RFC 1123 §2.1]: https://www.rfc-editor.org/rfc/rfc1123#section-2.1
// [RFC 3986 §3.2.2]: https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2
const RegistryHost = `(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?`

// HeaderNamePattern is an [RFC 9110 §5.6.2] token.
//
// [RFC 9110 §5.6.2]: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2
const HeaderNamePattern = "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"

const (
	MaxTemplateBytes  = 4096
	MaxURLBytes       = 2048
	MaxClientIDBytes  = 1024
	MaxMCPNameBytes   = 1024
	MaxAccessRules    = 256
	MaxCallers        = 256
	MaxArgs           = 64
	MaxRemoteHeaders  = 64
	MinPort, MaxPort  = 1, 65535
	MaxTTLSeconds     = 86400
	BuildRecordSchema = 1
)

// Architectures are the CPU architectures an app may be built for.
var Architectures = []string{"amd64", "arm64"}

// The kinds of a variable.
const (
	KindConfig = "config"
	KindSecret = "secret"
)

// HookVersionPattern is a [semantic version] without build metadata, which names a lifecycle boundary directory.
//
// [semantic version]: https://semver.org/spec/v2.0.0.html
const HookVersionPattern = `^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$`

// UnversionedHookEvents run directly under hooks/, and VersionedHookEvents under hooks/<version>/.
var (
	UnversionedHookEvents = []string{"pre-install", "post-install", "pre-delete", "post-delete"}
	VersionedHookEvents   = []string{"pre-upgrade", "post-upgrade", "pre-downgrade", "post-downgrade"}
)

// HookRuntimes maps a hook file's extension to the runtime that runs it.
var HookRuntimes = map[string]string{".js": "node", ".ts": "node", ".py": "python", "": "executable"}

func int64p(value int64) *int64 { return &value }

func anchored(pattern string) string { return "^" + pattern + "$" }

var boolean = rule.Boolean{}

var (
	AppName = rule.Text{Name: "AppName", Pattern: anchored(DNSLabelPattern), MinBytes: 1, MaxBytes: MaxAppNameBytes,
		Excluded: ReservedAppNames}
	SessionName    = rule.Text{Name: "SessionName", Pattern: anchored(DNSLabelPattern), MinBytes: 1, MaxBytes: MaxDNSLabelBytes}
	RequestID      = rule.Text{Name: "RequestID", Pattern: anchored(DNSLabelPattern), MinBytes: 1, MaxBytes: MaxDNSLabelBytes}
	EnvName        = rule.Text{Name: "EnvName", Pattern: EnvNamePattern, MinBytes: 1, MaxBytes: MaxEnvNameBytes, Excluded: ReservedEnv}
	Template       = rule.Text{Name: "Template", MaxBytes: MaxTemplateBytes, SingleLine: true}
	InputValue     = rule.Text{Name: "InputValue", SingleLine: true}
	ConfigRevision = rule.Text{Name: "ConfigRevision", Pattern: `^v-[0-9a-f]{24}$`}
	Digest         = rule.Text{Name: "Digest", Pattern: anchored(SHA256Digest)}
	ImageRef       = rule.Text{Name: "ImageRef", MaxBytes: MaxURLBytes,
		Pattern: anchored(RegistryHost + `/` + RepositoryName + `(?::` + Tag + `)?@` + SHA256Digest)}
	Port = rule.Integer{Name: "Port", Min: int64p(MinPort), Max: int64p(MaxPort)}
	// MountPath is a browser path in canonical form, which needs no escape, and ends in / only as /.
	MountPath  = rule.Text{Name: "MountPath", Pattern: `^/(?:[^?#%\\]*[^/?#%\\])?$`, MaxBytes: MaxURLBytes}
	RemoteURL  = rule.Text{Name: "RemoteURL", Pattern: `^https://`, MaxBytes: MaxURLBytes, SingleLine: true}
	HeaderName = rule.Text{Name: "HeaderName", Pattern: HeaderNamePattern}
	EgressHost = rule.Text{Name: "EgressHost", MinBytes: 1, SingleLine: true}
	Scope      = rule.Text{Name: "Scope", Pattern: ScopePattern, MinBytes: 1, MaxBytes: MaxScopeBytes}
	MCPName    = rule.Text{Name: "MCPName", MinBytes: 1, MaxBytes: MaxMCPNameBytes, SingleLine: true}
	ClientID   = rule.Text{Name: "ClientID", MinBytes: 1, MaxBytes: MaxClientIDBytes, SingleLine: true}
	// Revision is a session's resourceVersion, which the server chooses.
	Revision = rule.Text{Name: "Revision"}
)

func enumeration(name string, values ...string) rule.Enumeration {
	return rule.Enumeration{Name: name, Values: values}
}

var (
	Mode            = enumeration("Mode", "development", "production")
	VariableKind    = enumeration("VariableKind", KindConfig, KindSecret)
	Architecture    = enumeration("Architecture", Architectures...)
	RegistryType    = enumeration("RegistryType", "oci", "npm", "pypi")
	Phase           = enumeration("Phase", "Pending", "Applying", "Running", "WaitingForAuthorization", "Failed", "Succeeded", "Cancelled")
	ImportPhase     = enumeration("ImportPhase", "Pending", "Running", "Succeeded", "Failed")
	ConditionType   = enumeration("ConditionType", "Ready", "Available", "Accepted", "Degraded", "Expired", "EgressRestricted")
	ConditionStatus = enumeration("ConditionStatus", "True", "False")
	ConditionReason = enumeration("ConditionReason",
		"InvalidIdentity", "InvalidExpiry", "InvalidSpec", "Deleting", "LeaseExpired", "ProgressDeadlineExceeded",
		"LeaseActive", "ReconcileFailed", "Progressing", "ResourcesReady", "WorkloadUnavailable", "Serving",
		"AccessConfigurationUnavailable", "WaitingForConfiguration", "RuntimeNamespaceTerminating", "Provisioning",
		"InstallationPolicy", "LifecyclePending", "LifecycleApplying", "LifecycleRunning",
		"LifecycleWaitingForAuthorization", "LifecycleFailed", "LifecycleSucceeded")
	ErrorCode = enumeration("ErrorCode",
		"invalid_request", "not_found", "forbidden", "unauthorized", "unavailable", "conflict", "method_not_allowed",
		"precondition_failed", "precondition_required", "baseline_unknown", "authorization_required",
		"insufficient_scope", "rate_limited", "registration_failed")
	HookEvent   = enumeration("HookEvent", slices.Concat(UnversionedHookEvents, VersionedHookEvents)...)
	HookRuntime = enumeration("HookRuntime", slices.Compact(slices.Sorted(maps.Values(HookRuntimes)))...)
	HookVersion = rule.Text{Name: "HookVersion", Pattern: HookVersionPattern}
)
