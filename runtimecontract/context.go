package runtimecontract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Holon's waypoint sets these on a request it admits, after removing any X-Holon-* header the client sent.
// ContextHeader carries the signed caller context. CallerHeader carries the SPIFFE ID of the app of the same session
// that calls, a lifecycle hook's job calling as its app, and is absent when a person or the platform calls.
const (
	ContextHeader = "X-Holon-Context"
	CallerHeader  = "X-Holon-Caller"
)

func DecodeContextClaims(token string, claims any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid platform token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, claims)
}
