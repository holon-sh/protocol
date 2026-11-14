package model

import "github.com/holon-sh/protocol/internal/rule"

var text = rule.Text{}

func member(name string, r rule.Rule) rule.Member { return rule.Member{Name: name, Rule: r} }

func required(name string, r rule.Rule) rule.Member {
	return rule.Member{Name: name, Rule: r, Required: true}
}

// optional is a scalar member of a request whose zero value today's decoding cannot tell from its absence.
func optional(name string, r rule.Rule) rule.Member {
	return rule.Member{Name: name, Rule: r, ZeroIsAbsent: true}
}

// Empty is the object of a request or result that has no members.
var Empty = rule.Object{Name: "Empty"}

var ttlSeconds = rule.Member{Name: "ttlSeconds", Rule: rule.Integer{Min: int64p(1), Max: int64p(MaxTTLSeconds)}, Nullable: true,
	Description: "Detaches the new session, which then expires after this many seconds."}

var requestID = rule.Member{Name: "requestId", Rule: RequestID, ZeroIsAbsent: true, Description: "Makes a retried request idempotent."}

var CreateSessionRequest = rule.Object{Name: "CreateSessionRequest", Members: []rule.Member{
	requestID, ttlSeconds, required("apps", rule.List{Item: App}),
}}

// DesiredApps are the apps an update declares. A declared app replaces the stored app of its name.
var DesiredApps = rule.Object{Name: "DesiredApps", Members: []rule.Member{
	requestID, required("apps", rule.List{Item: App}),
}}

var (
	session          = required("session", text)
	expectedRevision = rule.Member{Name: "expectedRevision", Rule: Revision, ZeroIsAbsent: true, Description: "Writes only at this revision."}
	createOnly       = rule.Member{Name: "createOnly", Rule: boolean, ZeroIsAbsent: true, Description: "Writes only if nothing exists yet."}
)

// UpdateSessionRequest names its write precondition: exactly one of createOnly and expectedRevision, which the parse
// checks, since a false createOnly counts as absent.
var UpdateSessionRequest = rule.Object{Name: "UpdateSessionRequest", Members: []rule.Member{
	session, expectedRevision, createOnly,
	required("desired", DesiredApps),
	{Name: "remove", Rule: rule.List{Item: text}, Nullable: true, Description: "App names to delete from the session."},
}}

var SessionRequest = rule.Object{Name: "SessionRequest", Members: []rule.Member{session}}

var GetSessionRequest = rule.Object{Name: "GetSessionRequest", Members: []rule.Member{
	session, optional("revision", Revision),
}}

var DeleteSessionRequest = rule.Object{Name: "DeleteSessionRequest", Members: []rule.Member{
	session, required("expectedRevision", Revision), optional("skipHooks", boolean),
}}

var AuthorizeLifecycleRequest = rule.Object{Name: "AuthorizeLifecycleRequest", Members: []rule.Member{
	session, required("operation", text), optional("accessToken", text),
}}

var RetryLifecycleRequest = rule.Object{Name: "RetryLifecycleRequest", Members: []rule.Member{
	session, required("operation", text), required("expectedRevision", Revision),
}}

var UploadRequest = rule.Object{Name: "UploadRequest", Members: []rule.Member{
	{Name: "apps", Rule: rule.List{Item: text}, Required: true, Nullable: true},
}}

// variableMembers name a value by its scope and the apps it is set for. Without a session, the scope is production on
// the admin plane and every development session of the caller on the dev plane; with one, that session.
var variableMembers = []rule.Member{
	optional("session", SessionName),
	{Name: "apps", Rule: rule.List{Item: AppName, Set: true}, Required: true, Nullable: true},
	required("kind", VariableKind),
	required("variable", EnvName),
}

var VariableRequest = rule.Object{Name: "VariableRequest", Members: variableMembers}

var SetValueRequest = rule.Object{Name: "SetValueRequest", Members: append(variableMembers[:len(variableMembers):len(variableMembers)],
	rule.Member{Name: "revision", Rule: text, ZeroIsAbsent: true, Description: "The revision of a listed value that this one replaces."},
	rule.Member{Name: "value", Rule: InputValue, Nullable: true},
	optional("note", rule.Text{SingleLine: true}),
)}

var EgressRequest = rule.Object{Name: "EgressRequest", Members: []rule.Member{required("app", text)}}

var AppEgressPolicy = rule.Object{Name: "AppEgressPolicy", Members: []rule.Member{
	{Name: "allow", Rule: Egress, Description: "Omitted removes this app's ceiling."},
}}

var SetEgressRequest = rule.Object{Name: "SetEgressRequest", Members: []rule.Member{
	required("app", text), expectedRevision, createOnly, required("policy", AppEgressPolicy),
}}

var PackageSelection = rule.Object{Name: "PackageSelection", Members: []rule.Member{
	required("registryType", RegistryType), optional("identifier", text),
}}

var RegistrySource = rule.Object{Name: "RegistrySource", Members: []rule.Member{
	{Name: "name", Rule: text, Required: true, Description: "MCP Registry server identity in namespace/name form."},
	{Name: "version", Rule: text, Required: true, Description: "Exact server version; ranges and latest are unsupported."},
	{Name: "registry", Rule: text, ZeroIsAbsent: true, Description: "Registry URL; defaults to https://registry.modelcontextprotocol.io."},
	{Name: "package", Rule: PackageSelection, Nullable: true},
}}

var ImportRegistryPackageRequest = rule.Object{Name: "ImportRegistryPackageRequest", Members: []rule.Member{
	required("app", text), required("registry", RegistrySource),
}}

var GetImportRequest = rule.Object{Name: "GetImportRequest", Members: []rule.Member{required("id", text)}}

var appBuildRef = []rule.Member{required("repository", text), required("artifactDigest", text)}

var AppBuildRef = rule.Object{Name: "AppBuildRef", Members: appBuildRef}

// Results. The server writes them, so they are what this version writes; a reader tolerates a member or value it does
// not know.

var Owner = rule.Object{Name: "Owner", Members: []rule.Member{required("issuer", text), required("sub", text)}}

var LifecycleOperation = rule.Object{Name: "LifecycleOperation", Members: []rule.Member{
	member("initiator", Owner), required("id", text), member("retry", rule.Integer{}),
}}

var LifecycleStatus = rule.Object{Name: "LifecycleStatus", Members: []rule.Member{
	member("app", text), member("hook", text), member("readyApps", rule.List{Item: text}),
	required("id", text), required("phase", Phase), required("step", rule.Integer{}), required("attempt", rule.Integer{}),
	member("retry", rule.Integer{}), member("job", text), member("jobUID", text), member("deadline", text),
	member("message", text),
}}

var InstalledRelease = rule.Object{Name: "InstalledRelease", Members: []rule.Member{
	required("name", text), member("installed", ObservedApp), member("servingVersion", text),
}}

var SessionEndpoint = rule.Object{Name: "SessionEndpoint", Members: []rule.Member{required("name", text), required("url", text)}}

var Condition = rule.Object{Name: "Condition", Members: []rule.Member{
	required("type", ConditionType), required("status", ConditionStatus), member("observedGeneration", rule.Integer{}),
	{Name: "lastTransitionTime", Rule: text, Required: true, Nullable: true, Description: "An RFC 3339 time."},
	required("reason", ConditionReason), required("message", text),
}}

var SessionResponse = rule.Object{Name: "SessionResponse", Members: []rule.Member{
	member("operation", LifecycleOperation), member("lifecycle", LifecycleStatus),
	member("releases", rule.List{Item: InstalledRelease}), member("detached", boolean),
	member("buildArchitectures", rule.List{Item: Architecture}), required("uid", text),
	{Name: "apps", Rule: rule.List{Item: ObservedApp}, Required: true, Nullable: true},
	member("generation", rule.Integer{}), required("name", text),
	{Name: "endpoints", Rule: rule.List{Item: SessionEndpoint}, Required: true, Nullable: true},
	{Name: "conditions", Rule: rule.List{Item: Condition}, Required: true, Nullable: true},
	member("expiresAt", text), required("revision", Revision),
}}

var DeleteSessionResult = rule.Object{Name: "DeleteSessionResult", Members: []rule.Member{
	required("deleted", boolean), member("session", SessionResponse),
}}

var UploadGrant = rule.Object{Name: "UploadGrant", Members: []rule.Member{
	required("grant", text), required("registry", text),
	required("repositories", rule.Map{Key: text, Value: text}),
	required("expiresAt", text),
}}

var ConfigValue = rule.Object{Name: "ConfigValue", Members: []rule.Member{
	member("session", text),
	{Name: "apps", Rule: rule.List{Item: text}, Required: true, Nullable: true},
	required("kind", VariableKind), required("variable", text), required("revision", text), member("value", text),
	member("note", text), required("updatedAt", text), member("updatedBy", text),
}}

var ConfigValues = rule.Object{Name: "ConfigValues", Members: []rule.Member{
	{Name: "values", Rule: rule.List{Item: ConfigValue}, Required: true, Nullable: true},
}}

var EgressStatus = rule.Object{Name: "EgressStatus", Members: []rule.Member{
	required("reconciled", boolean), required("rolloutComplete", boolean), required("targets", rule.Integer{}),
	required("pending", rule.Integer{}), required("degraded", boolean), member("message", text),
}}

var EgressResponse = rule.Object{Name: "EgressResponse", Members: []rule.Member{
	member("allow", Egress), required("revision", text), required("app", text), required("status", EgressStatus),
}}

var Import = rule.Object{Name: "Import", Members: []rule.Member{
	required("id", text), required("phase", ImportPhase), member("message", text), member("build", AppBuildRef),
}}

var ResolvedAppBuild = rule.Object{Name: "ResolvedAppBuild", Members: append(append(appBuildRef[:len(appBuildRef):len(appBuildRef)],
	buildRecordMembers...), member("image", text))}

var InstallationReference = rule.Object{Name: "InstallationReference", Members: []rule.Member{
	required("origin", rule.Text{MinBytes: 1}), required("uid", rule.Text{MinBytes: 1, MaxBytes: 128}),
}}

var AccountManagement = rule.Object{Name: "AccountManagement", Members: []rule.Member{
	member("profileURL", text), member("securityURL", text), member("sessionsURL", text),
}}

var OAuthInfo = rule.Object{Name: "OAuthInfo", Members: []rule.Member{
	required("issuer", text), required("adminAudience", text), required("cliClientID", text),
	member("accountManagement", AccountManagement), member("peopleManagement", boolean),
}}

// Info describes an installation's capabilities.
var Info = rule.Object{Name: "Info", Members: []rule.Member{
	required("installation", InstallationReference),
	{Name: "oauth", Rule: OAuthInfo, Required: true, Nullable: true, Description: "null when identity is disabled."},
	required("version", text), member("imageRepositoryPrefix", text),
	member("buildArchitectures", rule.List{Item: Architecture}),
}}

var Error = rule.Object{Name: "Error", Members: []rule.Member{
	member("loginUrl", text), required("code", ErrorCode), required("message", text),
}}

// ErrorResponse is the control plane's error envelope.
var ErrorResponse = rule.Object{Name: "ErrorResponse", Members: []rule.Member{required("error", Error)}}
