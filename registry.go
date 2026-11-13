package protocol

import (
	"cmp"
	"errors"
	"net"
	"net/url"
	"strings"
)

const MCPRegistryOrigin = "https://registry.modelcontextprotocol.io"

type RegistryRef struct {
	Name     string `description:"MCP Registry server identity in namespace/name form."                json:"name"               required:"true"`
	Version  string `description:"Exact server version; ranges and latest are unsupported."            json:"version"            required:"true"`
	Registry string `description:"Registry URL; defaults to https://registry.modelcontextprotocol.io." json:"registry,omitempty"`
}

func (r RegistryRef) RegistryURL() string {
	return strings.TrimRight(cmp.Or(r.Registry, MCPRegistryOrigin), "/")
}

// The Registry resolves latest to whichever version is current, so a pin must name the version.
func (r RegistryRef) Validate() error {
	if r.Name == "" || r.Version == "" || strings.EqualFold(r.Version, "latest") {
		return errors.New("server name and exact version are required; latest is unsupported")
	}
	return ValidateRegistry(r.RegistryURL())
}

func ValidateRegistry(registry string) error {
	u, err := url.Parse(registry)
	if err == nil {
		host := u.Hostname()
		loopback := host == "localhost" || strings.HasSuffix(host, ".localhost") || net.ParseIP(host).IsLoopback()
		if u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Scheme == "https" || u.Scheme == "http" && loopback) {
			return nil
		}
	}
	return errors.New("MCP registry must be an HTTPS URL (loopback HTTP is allowed)")
}

type RegistryHeader struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Input       Input  `json:"input"`
}
