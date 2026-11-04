package protocol

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Info describes installation capabilities. OAuth is present and null when identity is disabled.
type Info struct {
	Installation          InstallationReference `json:"installation"`
	OAuth                 *OAuthInfo            `json:"oauth"`
	Version               string                `json:"version"`
	ImageRepositoryPrefix string                `json:"imageRepositoryPrefix,omitempty"`
	BuildArchitectures    []string              `json:"buildArchitectures,omitempty"`
}

// OAuthInfo supplies the issuer, audience and client settings for control-plane authentication.
type OAuthInfo struct {
	Issuer            string             `json:"issuer"`
	AdminAudience     string             `json:"adminAudience"`
	CLIClientID       string             `json:"cliClientID"`
	AccountManagement *AccountManagement `json:"accountManagement,omitempty"`
	PeopleManagement  bool               `json:"peopleManagement,omitempty"`
}

// AccountManagement contains provider-owned self-service pages. Omitted links
// mean that the provider does not advertise that capability.
type AccountManagement struct {
	ProfileURL  string `json:"profileURL,omitempty"`
	SecurityURL string `json:"securityURL,omitempty"`
	SessionsURL string `json:"sessionsURL,omitempty"`
}

func (info *Info) UnmarshalJSON(data []byte) error {
	type plainInfo Info
	return DecodeJSONFields(data, (*plainInfo)(info), "oauth")
}

const (
	APIPathInfo           = "/.well-known/holon"
	HeaderInstallationUID = "X-Holon-Installation-UID"
)

type InstallationReference struct {
	Origin string `json:"origin" minLength:"1"   required:"true"`
	UID    string `json:"uid"    maxLength:"128" minLength:"1"   required:"true"`
}

func (p InstallationReference) Validate() error {
	if _, err := CanonicalOrigin(p.Origin); err != nil || p.UID == "" || len(p.UID) > 128 ||
		strings.ContainsFunc(p.UID, unicode.IsSpace) || strings.ContainsFunc(p.UID, unicode.IsControl) {
		return errors.New("invalid installation reference")
	}
	return nil
}

func CanonicalOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("public origin is invalid")
	}
	hostname := parsed.Hostname()
	ip := net.ParseIP(hostname)
	validDNS := ip == nil && ValidDNSName(hostname)
	validHostname := hostname == "localhost" || ip.IsLoopback() || validDNS && strings.Contains(hostname, ".")
	port := parsed.Port()
	portNumber, _ := strconv.Atoi(port)
	validPort := port == "" || ValidPort(portNumber) && strconv.Itoa(portNumber) == port
	if parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		!validHostname ||
		!validPort ||
		strings.HasSuffix(parsed.Host, ":") ||
		parsed.Scheme != "https" {
		return "", errors.New("public origin is invalid")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}
