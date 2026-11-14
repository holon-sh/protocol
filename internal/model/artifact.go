package model

import "github.com/holon-sh/protocol/internal/rule"

// singleLine is a template without the declaration's length bound, which a build record does not have.
var singleLine = rule.Text{SingleLine: true}

// BuildRuntime is how a built app runs.
var BuildRuntime = rule.Object{Name: "BuildRuntime", Members: []rule.Member{
	member("icons", rule.List{Item: Icon}),
	required("port", Port),
	member("args", rule.List{Item: singleLine}),
	member("env", rule.Map{Key: EnvName, Value: Input, MaxEntries: MaxEnvEntries}),
	member("envTemplates", rule.Map{Key: EnvName, Value: singleLine}),
	member("requires", rule.List{Item: text}),
	member("egress", Egress),
}}

var buildRecordMembers = []rule.Member{
	required("schemaVersion", rule.Integer{Min: int64p(BuildRecordSchema), Max: int64p(BuildRecordSchema)}),
	required("appName", AppName),
	member("serverName", text),
	member("serverVersion", text),
	member("title", text),
	member("description", text),
	required("runtime", BuildRuntime),
	{Name: "unsupportedReasons", Rule: rule.List{Item: text}, Required: true, Nullable: true},
}

// BuildRecord is the metadata document stored beside an app's built image.
var BuildRecord = rule.Object{Name: "BuildRecord", Members: buildRecordMembers}
