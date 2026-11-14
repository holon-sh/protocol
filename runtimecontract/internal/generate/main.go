// Command generate writes the runtime contract's schema.json and names.json into the directory it is given.
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/holon-sh/protocol"
	"github.com/holon-sh/protocol/internal/rule"
	"github.com/holon-sh/protocol/runtimecontract"
	"github.com/holon-sh/protocol/runtimecontract/internal/model"
)

type name struct {
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Go          string `json:"go"`
	Description string `json:"description"`
}

var names = []name{
	{"header", runtimecontract.ContextHeader, "runtimecontract.ContextHeader", "The signed context of a request the waypoint admitted. Its payload follows schema.json."},
	{"header", runtimecontract.CallerHeader, "runtimecontract.CallerHeader", "The app of the same session that calls, as <session>/<app>."},
	{"header prefix", runtimecontract.HeaderPrefix, "runtimecontract.HeaderPrefix", "Begins every header the platform owns. An SDK removes these from what app code sees."},
	{"header", protocol.HeaderAuthorization, "protocol.HeaderAuthorization", "An SDK removes it from what app code sees, and sends a dependency's token in it."},
	{"value prefix", protocol.BearerPrefix, "protocol.BearerPrefix", "Begins the Authorization value an SDK sends to a dependency."},
	{"header", runtimecontract.ForwardedHostHeader, "runtimecontract.ForwardedHostHeader", "The host of the session's audience, set by the waypoint."},
	{"header", runtimecontract.ForwardedProtoHeader, "runtimecontract.ForwardedProtoHeader", "The scheme of the session's audience, set by the waypoint."},
	{"variable", protocol.PlatformEnv, "protocol.PlatformEnv", "Set to PlatformEnabled in every app container."},
	{"value", runtimecontract.PlatformEnabled, "runtimecontract.PlatformEnabled", "The value of PlatformEnv inside Holon. Any other value, or none, means outside Holon."},
	{"variable", runtimecontract.HostEnv, "runtimecontract.HostEnv", "The address the app listens on."},
	{"variable", runtimecontract.PortEnv, "runtimecontract.PortEnv", "The port the app listens on."},
	{"variable suffix", protocol.DependencyEnvSuffix, "protocol.DependencyEnvSuffix", "Ends the variable that holds a dependency's endpoint: the dependency's name in upper case, with - as _."},
	{"variable suffix", runtimecontract.DependencyTokenEnvSuffix, "runtimecontract.DependencyTokenEnvSuffix", "Ends the variable whose value an SDK sends as a dependency's bearer token. The platform does not set it."},
	{"variable", runtimecontract.OverlayFileEnv, "runtimecontract.OverlayFileEnv", "The file that records a development app's latest source overlay."},
	{"variable", protocol.OTELServiceNameEnv, "protocol.OTELServiceNameEnv", "Set by the platform when it collects telemetry."},
	{"variable", protocol.OTELResourceAttributesEnv, "protocol.OTELResourceAttributesEnv", "Set by the platform when it collects telemetry."},
	{"variable", protocol.OTELExporterOTLPEndpointEnv, "protocol.OTELExporterOTLPEndpointEnv", "Set by the platform when it collects telemetry."},
	{"variable", protocol.OTELExporterOTLPProtocolEnv, "protocol.OTELExporterOTLPProtocolEnv", "Set by the platform when it collects telemetry."},
	{"path", protocol.MCPPath, "protocol.MCPPath", "The MCP endpoint the platform calls."},
	{"path prefix", protocol.MCPPathPrefix, "protocol.MCPPathPrefix", "Followed by one segment, an MCP endpoint an SDK also serves."},
	{"path", runtimecontract.ReloadPath, "runtimecontract.ReloadPath", "Where the platform posts a development app's source overlay."},
	{"media type", runtimecontract.OverlayMediaType, "runtimecontract.OverlayMediaType", "The media type of a source overlay."},
	{"file", runtimecontract.PlanFile, "runtimecontract.PlanFile", "The file in an overlay that says how to install, prepare and start the app."},
	{"claim value", runtimecontract.ContextIssuer, "runtimecontract.ContextIssuer", "The iss of every context Holon signs."},
}

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatal("usage: generate <directory>")
	}
	schema, err := rule.Schema(model.Claims,
		"The payload of the compact JWS in X-Holon-Context. The waypoint verifies its signature before an app sees it.",
		model.Context, model.Caller)
	if err != nil {
		log.Fatal(err)
	}
	list, err := rule.Encode(names)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(os.Args[1], 0o755); err != nil {
		log.Fatal(err)
	}
	for file, data := range map[string][]byte{"schema.json": schema, "names.json": list} {
		if err := os.WriteFile(filepath.Join(os.Args[1], file), data, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
