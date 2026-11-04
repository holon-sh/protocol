package introspection

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
)

var tokenFields = []string{"active", "token_type", "iss", "sub", "client_id", "exp", "nbf", "aud", "scope", "act"}

func additionalClaims(data []byte) (map[string]json.RawMessage, error) {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}
	if claims == nil {
		return nil, errors.New("claims must be an object")
	}
	maps.DeleteFunc(claims, tokenField)
	if len(claims) == 0 {
		return nil, nil
	}
	return claims, nil
}

func (r *Result) UnmarshalJSON(data []byte) error {
	type plain Result
	var wire struct {
		plain

		Audience json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	claims, err := additionalClaims(data)
	if err != nil {
		return err
	}
	if !wire.Active {
		*r = Result{}
		return nil
	}
	if len(wire.Audience) != 0 {
		if err := json.Unmarshal(wire.Audience, &wire.plain.Audience); err != nil {
			var audience string
			if err := json.Unmarshal(wire.Audience, &audience); err != nil {
				return err
			}
			wire.plain.Audience = []string{audience}
		}
	}
	*r = Result(wire.plain)
	r.Claims = claims
	return nil
}

func (r Result) MarshalJSON() ([]byte, error) {
	if !r.Active {
		return []byte(`{"active":false}`), nil
	}
	type plain Result
	data, err := json.Marshal(plain(r))
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	claims := maps.Clone(r.Claims)
	maps.DeleteFunc(claims, tokenField)
	maps.Copy(fields, claims)
	return json.Marshal(fields)
}

func tokenField(name string, _ json.RawMessage) bool { return slices.Contains(tokenFields, name) }
