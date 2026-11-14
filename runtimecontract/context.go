package runtimecontract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/holon-sh/protocol"
)

// Holon's waypoint sets these on a request it admits, after removing any X-Holon-* header the client sent.
// ContextHeader carries the signed caller context. CallerHeader carries "<session>/<app>", the app of the same session
// that calls, a lifecycle hook's job calling as its app, and is absent when a person or the platform calls.
const (
	ContextHeader = "X-Holon-Context"
	CallerHeader  = "X-Holon-Caller"
	// HeaderPrefix begins every header name the platform owns. An app's SDK removes each such header, and
	// Authorization, before app code sees a request.
	HeaderPrefix = "X-Holon-"
)

// ContextIssuer is the iss of every context Holon signs.
const ContextIssuer = "urn:holon:identity"

var (
	contextForm = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	callerForm  = regexp.MustCompile(`^[^/]+/[^/]+$`)
)

// Claims is the payload of the compact JWS that ContextHeader carries, in the order Holon writes its members.
type Claims struct {
	Issuer    string                   `json:"iss"`
	Subject   string                   `json:"sub"`
	Audience  []string                 `json:"aud"`
	ExpiresAt int64                    `json:"exp"`
	IssuedAt  int64                    `json:"iat"`
	Principal *Principal               `json:"principal,omitempty"`
	FlowID    string                   `json:"flowId"`
	Hook      *protocol.HookInvocation `json:"hook,omitempty"`
}

// Principal is the person or client a context acts for. Act is the delegation claim of RFC 8693 §4.1, a JSON object,
// and Claims are the identity provider's other claims about the person.
type Principal struct {
	Issuer   string                     `json:"iss"`
	Subject  string                     `json:"sub"`
	Scope    string                     `json:"scope,omitempty"`
	ClientID string                     `json:"client_id"`
	Act      json.RawMessage            `json:"act,omitempty"`
	Claims   map[string]json.RawMessage `json:"claims,omitempty"`
}

// Caller is the app of the same session that made a request, as CallerHeader names it.
type Caller struct {
	Session string
	App     string
}

// ParseCaller reads a value of CallerHeader.
func ParseCaller(value string) (Caller, error) {
	if !callerForm.MatchString(value) {
		return Caller{}, errors.New("a caller is <session>/<app>")
	}
	session, app, _ := strings.Cut(value, "/")
	return Caller{Session: session, App: app}, nil
}

func DecodeContextClaims(token string, claims any) error {
	payload, err := contextPayload(token)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, claims)
}

func contextPayload(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid platform token")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}
