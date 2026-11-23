package protocol

import (
	"errors"
	"net/url"
	"strings"
)

func AppPath(name string) string {
	return MCPPathPrefix + name
}

type Host string

const (
	BaseHost    Host = "base"
	DevHost     Host = "dev"
	AdminHost   Host = "admin"
	AccountHost Host = "account"
	SessionHost Host = "session"
)

var hostLabels = map[Host]string{BaseHost: "", DevHost: "dev.", AdminHost: "admin.", AccountHost: "account."}

func HostOrigin(origin string, host Host, sessionID string) (string, error) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return "", err
	}
	label, ok := hostLabels[host]
	if host == SessionHost {
		if !ValidSessionName(sessionID) {
			return "", errors.New("session id is invalid")
		}
		label, ok = sessionID+".", true
	}
	if !ok {
		return "", errors.New("host is invalid")
	}
	return HTTPSPrefix + label + strings.TrimPrefix(canonical, HTTPSPrefix), nil
}

func ParseHost(origin, host string) (Host, string, bool) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return "", "", false
	}
	baseHost := strings.TrimPrefix(canonical, HTTPSPrefix)
	for kind, label := range hostLabels {
		if host == label+baseHost {
			return kind, "", true
		}
	}
	sessionID, found := strings.CutSuffix(host, "."+baseHost)
	if !found || !ValidSessionName(sessionID) {
		return "", "", false
	}
	return SessionHost, sessionID, true
}

func ParseControlAudience(origin, resource string) (Host, bool) {
	host, _, ok := ParseHost(origin, strings.TrimPrefix(resource, HTTPSPrefix))
	return host, ok && strings.HasPrefix(resource, HTTPSPrefix) && host != BaseHost && host != SessionHost
}

func RegistryHost(origin string) string {
	canonical, _ := CanonicalOrigin(origin)
	return strings.TrimPrefix(canonical, HTTPSPrefix)
}

func ParseAppPath(path string) (string, bool) {
	name, ok := strings.CutPrefix(path, MCPPathPrefix)
	return name, ok && ValidAppName(name)
}

func ParseAppResource(resource string) (string, string, bool) {
	u, err := url.Parse(resource)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.RawPath != "" || u.String() != resource {
		return "", "", false
	}
	name, ok := ParseAppPath(u.Path)
	return u.Scheme + "://" + u.Host, name, ok
}

var sessionHosts = map[string]Host{ModeProduction: BaseHost, ModeDevelopment: SessionHost}

func SessionAudience(origin, mode, sessionID string) (string, error) {
	host, ok := sessionHosts[mode]
	if !ok {
		return "", errors.New("session mode is invalid")
	}
	return HostOrigin(origin, host, sessionID)
}

func ParseSessionAudience(origin, audience string) (string, string, bool) {
	host, sessionID, _ := ParseHost(origin, strings.TrimPrefix(audience, HTTPSPrefix))
	mode := ModeDevelopment
	if host == BaseHost {
		mode = ModeProduction
	}
	expected, err := SessionAudience(origin, mode, sessionID)
	if err != nil || audience != expected {
		return "", "", false
	}
	return mode, sessionID, true
}
