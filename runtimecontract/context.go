package runtimecontract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const (
	ContextHeader = "X-Holon-Context"
	CallerHeader  = "X-Holon-Caller"
	ScopeHeader   = "X-Holon-Scope"
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
