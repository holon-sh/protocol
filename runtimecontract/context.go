package runtimecontract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Holon's waypoint sets these on a request it admits, after removing any X-Holon-* header the client sent.
// ContextHeader carries the signed caller context. CallerHeader carries "<session>/<app>", the app of the same session
// that calls, a lifecycle hook's job calling as its app, and is absent when a person or the platform calls.
const (
	ContextHeader = "X-Holon-Context"
	CallerHeader  = "X-Holon-Caller"
)

// An app sets these on a call it makes for a person. SubjectHeader names the person, the party on whose behalf the
// request is made ([RFC 8693 §2.1]). ActorHeader names the acting party ([RFC 8693 §2.1]), the app the sender acts for,
// and is set only when that app is not the sender.
//
// [RFC 8693 §2.1]: https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
const (
	SubjectHeader = "X-Holon-Subject"
	ActorHeader   = "X-Holon-Actor"
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
