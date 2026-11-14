// Command generate writes spec/control and spec/artifact into the spec directory it is given.
package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/holon-sh/protocol"
	"github.com/holon-sh/protocol/internal/model"
	"github.com/holon-sh/protocol/internal/rule"
)

type operation struct {
	Tool        string      `json:"tool"`
	Go          string      `json:"go"`
	Planes      []string    `json:"planes"`
	Scope       string      `json:"scope"`
	Request     string      `json:"request"`
	Response    string      `json:"response"`
	Description string      `json:"description"`
	request     rule.Object `json:"-"`
	response    rule.Object `json:"-"`
}

var (
	both  = []string{string(protocol.DevPlane), string(protocol.AdminPlane)}
	dev   = []string{string(protocol.DevPlane)}
	admin = []string{string(protocol.AdminPlane)}
)

const (
	read  = "read"
	write = "write"
	// registry marks a tool served only by an installation with an app registry.
	registry = " Served only when the installation has an app registry."
)

func op(tool, constant string, planes []string, scope string, request, response rule.Object, description string) operation {
	return operation{Tool: tool, Go: "protocol." + constant, Planes: planes, Scope: scope, Request: request.Name,
		Response: response.Name, Description: description, request: request, response: response}
}

var operations = []operation{
	op(protocol.ToolCreateSession, "ToolCreateSession", dev, write, model.CreateSessionRequest, model.SessionResponse,
		"Create a development session of the caller with the apps declared."),
	op(protocol.ToolGetSession, "ToolGetSession", both, read, model.GetSessionRequest, model.SessionResponse,
		"Read a session."),
	op(protocol.ToolUpdateSession, "ToolUpdateSession", both, write, model.UpdateSessionRequest, model.SessionResponse,
		"Declare apps in a session, replacing the stored apps of the same names, and remove others."),
	op(protocol.ToolDeleteSession, "ToolDeleteSession", both, write, model.DeleteSessionRequest, model.DeleteSessionResult,
		"Delete a session at a revision."),
	op(protocol.ToolRenewSession, "ToolRenewSession", dev, write, model.SessionRequest, model.SessionResponse,
		"Extend the lease of a development session."),
	op(protocol.ToolAuthorizeLifecycle, "ToolAuthorizeLifecycle", both, write, model.AuthorizeLifecycleRequest, model.Empty,
		"Authorize a lifecycle operation as the principal that started it."),
	op(protocol.ToolRetryLifecycle, "ToolRetryLifecycle", both, write, model.RetryLifecycleRequest, model.SessionResponse,
		"Retry a failed lifecycle operation at a revision."),
	op(protocol.ToolUploadGrant, "ToolUploadGrant", both, write, model.UploadRequest, model.UploadGrant,
		"Grant upload access to the repositories of the apps named."+registry),
	op(protocol.ToolSetValue, "ToolSetValue", both, write, model.SetValueRequest, model.Empty,
		"Set one config value or secret for exactly the apps named, linking them."),
	op(protocol.ToolDeleteValue, "ToolDeleteValue", both, write, model.VariableRequest, model.Empty,
		"Delete a config value or secret of the apps named."),
	op(protocol.ToolListValues, "ToolListValues", both, read, model.Empty, model.ConfigValues,
		"List the config values and secrets of the plane, without secret values."),
	op(protocol.ToolGetEgress, "ToolGetEgress", admin, read, model.EgressRequest, model.EgressResponse,
		"Read an app's egress ceiling and its rollout."),
	op(protocol.ToolSetEgress, "ToolSetEgress", admin, write, model.SetEgressRequest, model.EgressResponse,
		"Set an app's egress ceiling."),
	op(protocol.ToolImportRegistryPackage, "ToolImportRegistryPackage", both, write, model.ImportRegistryPackageRequest, model.Import,
		"Start importing an MCP Registry package as an app build."+registry),
	op(protocol.ToolGetImport, "ToolGetImport", both, read, model.GetImportRequest, model.Import,
		"Read an import."+registry),
	op(protocol.ToolResolveAppBuild, "ToolResolveAppBuild", both, read, model.AppBuildRef, model.ResolvedAppBuild,
		"Read an app build's record and image."),
}

// definitions are the control contract's named rules that no operation reaches, besides those that operations do.
var definitions = []rule.Rule{model.App, model.ObservedApp, model.Info, model.ErrorResponse, model.Mode, model.ErrorCode}

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: generate <spec directory>")
	}
	check(os.RemoveAll(filepath.Join(os.Args[1], "control", "inputs")))
	files := map[string][]byte{}
	defs := definitions
	for _, o := range operations {
		defs = append(defs, o.request, o.response)
		input, err := rule.Schema(o.request, "The input of the "+o.Tool+" tool. "+o.Description)
		check(err)
		files[filepath.Join("control", "inputs", o.Tool+".json")] = input
	}
	control, err := rule.Schema(rule.Opaque{},
		"The definitions of Holon's control contract. operations.json names the request and result of each tool.", defs...)
	check(err)
	files[filepath.Join("control", "schema.json")] = control
	files[filepath.Join("control", "operations.json")] = encode(operations)
	artifact, err := rule.Schema(model.BuildRecord,
		"The build record stored beside an app's built image. Its $defs also hold a lifecycle hook as an image's release lists it.",
		model.Release)
	check(err)
	files[filepath.Join("artifact", "schema.json")] = artifact
	for name, data := range files {
		path := filepath.Join(os.Args[1], name)
		check(os.MkdirAll(filepath.Dir(path), 0o755))
		check(os.WriteFile(path, data, 0o644))
	}
}

func encode(value any) []byte {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	check(encoder.Encode(value))
	return out.Bytes()
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
