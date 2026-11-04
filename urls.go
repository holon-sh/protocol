package protocol

import (
	"errors"
	"net/url"
	"strings"
)

func AppPath(name string) string {
	return MCPPathPrefix + name
}

type Plane string

const (
	BasePlane    Plane = "base"
	DevPlane     Plane = "dev"
	AdminPlane   Plane = "admin"
	SessionPlane Plane = "session"
)

var planeLabels = map[Plane]string{BasePlane: "", DevPlane: "dev.", AdminPlane: "admin."}

func PlaneOrigin(origin string, plane Plane, sessionID string) (string, error) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return "", err
	}
	label, ok := planeLabels[plane]
	if plane == SessionPlane {
		if !ValidDNSLabel(sessionID) || sessionID == "dev" || sessionID == "admin" {
			return "", errors.New("session id is invalid")
		}
		label, ok = sessionID+".", true
	}
	if !ok {
		return "", errors.New("plane is invalid")
	}
	return HTTPSPrefix + label + strings.TrimPrefix(canonical, HTTPSPrefix), nil
}

func ParseHost(origin, host string) (Plane, string, bool) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return "", "", false
	}
	baseHost := strings.TrimPrefix(canonical, HTTPSPrefix)
	for plane, label := range planeLabels {
		if host == label+baseHost {
			return plane, "", true
		}
	}
	sessionID, found := strings.CutSuffix(host, "."+baseHost)
	if !found || !ValidDNSLabel(sessionID) {
		return "", "", false
	}
	return SessionPlane, sessionID, true
}

func ParseControlAudience(origin, resource string) (Plane, bool) {
	plane, _, ok := ParseHost(origin, strings.TrimPrefix(resource, HTTPSPrefix))
	return plane, ok && strings.HasPrefix(resource, HTTPSPrefix) && (plane == DevPlane || plane == AdminPlane)
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

var sessionPlanes = map[string]Plane{ModeProduction: BasePlane, ModeDevelopment: SessionPlane}

func SessionAudience(origin, mode, sessionID string) (string, error) {
	plane, ok := sessionPlanes[mode]
	if !ok {
		return "", errors.New("session mode is invalid")
	}
	return PlaneOrigin(origin, plane, sessionID)
}

func ParseSessionAudience(origin, audience string) (string, string, bool) {
	plane, sessionID, _ := ParseHost(origin, strings.TrimPrefix(audience, HTTPSPrefix))
	mode := ModeDevelopment
	if plane == BasePlane {
		mode = ModeProduction
	}
	expected, err := SessionAudience(origin, mode, sessionID)
	if err != nil || audience != expected {
		return "", "", false
	}
	return mode, sessionID, true
}
