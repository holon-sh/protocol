package runtimecontract

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/holon-sh/protocol"
)

// Decision is what an app's SDK does with a request. A request off the MCP route goes to the SDK's page, and only
// Removed applies to it. On the route, a rejected request is answered 400, and an admitted one reaches the MCP server
// as Principal and Caller, without the headers Removed names. Context is the admitted context, which the SDK sends on
// with the app's calls to its dependencies while the request lasts.
type Decision struct {
	MCP       bool
	Reject    bool
	Principal *Principal
	Caller    *Caller
	Context   string
	Removed   []string
}

// Admit decides a request from the value of PlatformEnv, the request target's path before it is percent-decoded, and
// the request's headers. Only where PlatformEnv is PlatformEnabled does it read ContextHeader and CallerHeader, which
// the waypoint has verified and set there, and it rejects them when they are not what the waypoint sends: either
// header twice, a context that is not a compact JWS whose payload is a JSON object with a principal object or none,
// or a caller that is not <session>/<app>. It does not verify the context.
func Admit(platform, path string, header http.Header) Decision {
	decision := Decision{MCP: mcpRoute(path)}
	for name := range header {
		if strings.EqualFold(name, protocol.HeaderAuthorization) || len(name) >= len(HeaderPrefix) &&
			strings.EqualFold(name[:len(HeaderPrefix)], HeaderPrefix) {
			decision.Removed = append(decision.Removed, name)
		}
	}
	slices.Sort(decision.Removed)
	if !decision.MCP || platform != PlatformEnabled {
		return decision
	}
	rejected := Decision{MCP: true, Reject: true, Removed: decision.Removed}
	contexts, callers := header.Values(ContextHeader), header.Values(CallerHeader)
	if len(contexts) > 1 || len(callers) > 1 {
		return rejected
	}
	if len(contexts) == 1 {
		principal, err := admitContext(contexts[0])
		if err != nil {
			return rejected
		}
		decision.Context, decision.Principal = contexts[0], principal
	}
	if len(callers) == 1 {
		caller, err := ParseCaller(callers[0])
		if err != nil {
			return rejected
		}
		decision.Caller = &caller
	}
	return decision
}

// mcpRoute reports whether path is MCPPath, or MCPPathPrefix and one segment that does not decode to a dot segment or
// hold an encoded slash.
func mcpRoute(path string) bool {
	segment, found := strings.CutPrefix(path, protocol.MCPPathPrefix)
	if !found {
		return path == protocol.MCPPath
	}
	name, err := url.PathUnescape(segment)
	return err == nil && segment != "" && name != "." && name != ".." && !strings.Contains(name, "/")
}

// admitContext reads the principal of a context. Member names match exactly, the last of a repeated member counts,
// and members other than principal are not read.
func admitContext(token string) (*Principal, error) {
	if !contextForm.MatchString(token) {
		return nil, errors.New("a context is a compact JWS")
	}
	payload, err := contextPayload(token)
	if err != nil {
		return nil, err
	}
	// The principal is read apart, so that a repeated principal replaces the one before it instead of merging into it.
	var claims *struct {
		Principal jsontext.Value `json:"principal"`
	}
	if err := jsonv2.Unmarshal(payload, &claims, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, err
	}
	if claims == nil {
		return nil, errors.New("a context's payload is a JSON object")
	}
	if len(claims.Principal) == 0 || claims.Principal.Kind() == 'n' {
		return nil, nil
	}
	var principal Principal
	if err := jsonv2.Unmarshal(claims.Principal, &principal, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, err
	}
	switch jsontext.Value(principal.Act).Kind() {
	case 'n':
		principal.Act = nil
	case 0, '{':
	default:
		return nil, errors.New("act is a JSON object")
	}
	return &principal, nil
}
