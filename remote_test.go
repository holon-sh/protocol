package protocol_test

import (
	"strings"
	"testing"

	"github.com/holon-sh/protocol"
)

func TestRemoteHeaderContract(t *testing.T) {
	for _, name := range []string{"x-api-key", "Authorization", "x_api_key"} {
		if !protocol.ValidRemoteHeader(name) {
			t.Errorf("rejected %q", name)
		}
	}
	for _, name := range []string{"", "x api", "étag", "x-holon-tenant", "Mcp-Session-Id", "Content-Type", "cookie"} {
		if protocol.ValidRemoteHeader(name) {
			t.Errorf("accepted %q", name)
		}
	}
}

func TestOpenAPIRemoteBuildContract(t *testing.T) {
	model := "holon/upload/pokeapi@sha256:" + strings.Repeat("0123456789abcdef", 4)
	build := func(port int32, remote protocol.Remote) protocol.BuildRecord {
		return protocol.BuildRecord{SchemaVersion: 1, AppName: "pokeapi", Runtime: protocol.BuildRuntime{Port: port, Remote: &remote}}
	}
	if err := build(0, protocol.Remote{URL: "https://pokeapi.co", OpenAPI: model}).Validate(); err != nil {
		t.Fatalf("rejected an OpenAPI build: %v", err)
	}
	for name, record := range map[string]protocol.BuildRecord{
		"a port":         build(3000, protocol.Remote{URL: "https://pokeapi.co", OpenAPI: model}),
		"no model":       build(0, protocol.Remote{URL: "https://pokeapi.co"}),
		"a tagged model": build(0, protocol.Remote{URL: "https://pokeapi.co", OpenAPI: "holon/upload/pokeapi:latest"}),
		"headers":        build(0, protocol.Remote{URL: "https://pokeapi.co", OpenAPI: model, Headers: map[string]string{"x-api-key": "key"}}),
		"an HTTP server": build(0, protocol.Remote{URL: "http://pokeapi.co", OpenAPI: model}),
	} {
		if record.Validate() == nil {
			t.Errorf("accepted a remote build with %s", name)
		}
	}
}
