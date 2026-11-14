package model

import "github.com/holon-sh/protocol/internal/rule"

// Input is one variable an app declares. A literal is a value or a default, never both. A secret has neither, which
// the parse checks, since a variant here is chosen by a member's presence and isSecret may be false.
var Input = rule.Object{Name: "Input", Members: []rule.Member{
	{Name: "isRequired", Rule: boolean},
	{Name: "isSecret", Rule: boolean},
	{Name: "value", Rule: InputValue},
	{Name: "default", Rule: InputValue},
}, Unions: []rule.Union{{Variants: []rule.Variant{{Select: "value"}, {Select: "default"}, {}}}}}

var OAuthRequirement = rule.Object{Name: "OAuthRequirement", Members: []rule.Member{
	{Name: "scopes", Rule: rule.List{Item: Scope, Set: true}, Description: "OAuth scope tokens. Without any, the rule requires authentication only."},
}}

var AccessRule = rule.Object{Name: "AccessRule", Members: []rule.Member{
	{Name: "oauth", Rule: OAuthRequirement, Description: "Absent for public access."},
	{Name: "callers", Rule: rule.List{Item: AppName, MaxItems: MaxCallers, Set: true},
		Description: "The apps that may call. Absent admits every caller, and [] none."},
}}

var AppAccess = rule.Object{Name: "AppAccess", Members: []rule.Member{
	{Name: "server", Rule: AccessRule, Required: true},
	{Name: "tools", Rule: rule.Map{Key: MCPName, Value: AccessRule, MaxEntries: MaxAccessRules},
		Description: "Tool rules replace the server rule."},
}}

var OAuthClient = rule.Object{Name: "OAuthClient", Members: []rule.Member{
	{Name: "clientID", Rule: ClientID, Required: true, Description: "A template whose placeholders each name a config input."},
	{Name: "clientSecret", Rule: EnvName, Description: "The secret input that holds the client secret."},
}}

var Remote = rule.Object{Name: "Remote", Members: []rule.Member{
	{Name: "url", Rule: RemoteURL, Required: true, Description: "A template over the app's inputs."},
	{Name: "headers", Rule: rule.Map{Key: HeaderName, Value: Template, MaxEntries: MaxRemoteHeaders},
		Description: "Each header's template over the app's inputs."},
}}

var EgressDestination = rule.Object{Name: "EgressDestination", Members: []rule.Member{
	{Name: "host", Rule: EgressHost, Required: true,
		Description: "An exact DNS hostname or unicast IP address. {NAME} stands for a non-secret input."},
	{Name: "ports", Rule: rule.List{Item: Port, MinItems: 1}, Required: true},
}}

var Egress = rule.List{Name: "Egress", Item: EgressDestination}

var Icon = rule.Object{Name: "Icon", Members: []rule.Member{
	{Name: "src", Rule: rule.Text{}, Required: true},
	{Name: "mimeType", Rule: rule.Text{}},
	{Name: "sizes", Rule: rule.List{Item: rule.Text{}}},
	{Name: "theme", Rule: rule.Text{}},
}}

var Hook = rule.Object{Name: "Hook", Members: []rule.Member{
	{Name: "event", Rule: HookEvent, Required: true},
	{Name: "version", Rule: HookVersion, Description: "The lifecycle boundary of an upgrade or downgrade hook."},
	{Name: "path", Rule: rule.Text{}, Required: true, Description: "hooks/[<version>/]<event>[.js|.ts|.py], under the working directory."},
	{Name: "runtime", Rule: HookRuntime, Required: true},
	{Name: "checksum", Rule: Digest, Required: true},
}}

var Artifact = rule.Object{Name: "Artifact", Members: []rule.Member{
	{Name: "architecture", Rule: Architecture, Required: true},
	{Name: "workingDir", Rule: rule.Text{}, Required: true},
	{Name: "hooks", Rule: rule.List{Item: Hook}},
}}

var Release = rule.Object{Name: "Release", Members: []rule.Member{
	{Name: "name", Rule: rule.Text{}},
	{Name: "version", Rule: rule.Text{}},
	{Name: "artifacts", Rule: rule.List{Item: Artifact}},
}}

var applied = rule.Map{Key: EnvName, Value: ConfigRevision, MaxEntries: MaxEnvEntries}

// source is the union of an app's runtime: an image with its port, a remote server, or a development overlay.
var source = rule.Union{Variants: []rule.Variant{
	{Select: "image", Members: []string{"port", "args", "envTemplates", "mount"}},
	{Select: "remote"},
	{Select: "overlay", Members: []string{"args", "envTemplates", "mount"}},
}}

// imagePort requires a port with an image: an app has a port and maybe an image, or neither. The source union forbids
// a port without an image.
var imagePort = rule.Union{Variants: []rule.Variant{{Select: "port", Members: []string{"image"}}, {}}}

// appMembers are the members an app's declaration and its stored form share. A declaration may hold null for five
// of them, which today's path reads as absent. The server never writes one.
func appMembers(declared bool, appliedDescription string) []rule.Member {
	return []rule.Member{
		{Name: "icons", Rule: rule.List{Item: Icon}, Nullable: declared},
		{Name: "mount", Rule: MountPath, Description: "The app's browser path in production. Defaults to /<name>."},
		{Name: "oauth", Rule: OAuthClient, Nullable: declared},
		{Name: "remote", Rule: Remote, Nullable: declared},
		{Name: "access", Rule: AppAccess, Required: true},
		{Name: "name", Rule: AppName, Required: true},
		{Name: "image", Rule: ImageRef},
		{Name: "port", Rule: Port, Description: "Required with an image, and allowed only with one."},
		{Name: "args", Rule: rule.List{Item: Template, MaxItems: MaxArgs}, Nullable: declared,
			Description: "Each replaces one of the image's command arguments, when every input its template names has a value."},
		{Name: "requires", Rule: rule.List{Item: AppName, Set: true}, Nullable: declared},
		{Name: "egress", Rule: Egress},
		{Name: "env", Rule: rule.Map{Key: EnvName, Value: Input, MaxEntries: MaxEnvEntries}},
		{Name: "envTemplates", Rule: rule.Map{Key: EnvName, Value: Template, MaxEntries: MaxEnvEntries},
			Description: "Variables set from templates over the app's inputs, when every input a template names has a value."},
		{Name: "applied", Rule: applied, Description: appliedDescription},
		{Name: "imported", Rule: boolean, Description: "Marks an app installed from an MCP Registry package."},
		{Name: "overlay", Rule: Digest, Description: "The digest of a development app's server source."},
	}
}

// App is an app as a client declares it.
var App = rule.Object{Name: "App", Members: appMembers(true, "Written by the server. A client may send it only empty."),
	Unions: []rule.Union{source, imagePort}}

// ObservedApp is an app as the server stores and returns it: its declaration and what the server added.
var ObservedApp = rule.Object{Name: "ObservedApp", Members: append(appMembers(false, "The revision of each value the app runs with."),
	rule.Member{Name: "release", Rule: Release},
	rule.Member{Name: "supplied", Rule: rule.Map{Key: EnvName, Value: Input, MaxEntries: MaxEnvEntries},
		Description: "Values set for the app that it does not declare."},
), Unions: []rule.Union{source, imagePort}}
