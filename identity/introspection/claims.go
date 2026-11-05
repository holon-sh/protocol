package introspection

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/holon-sh/protocol/oauthscope"
)

var tokenFields = []string{"active", "token_type", "iss", "sub", "client_id", "exp", "nbf", "aud", "scope", "act"}

// UnmarshalJSON reads an [RFC 7662 §2.2] answer as package profile requires it. An answer without active, or an active
// one lacking a required field or with a scope outside [RFC 6749 §3.3], is an error. Only a Bearer token can be active:
// token_type compares as [RFC 6749 §5.1] says, and any other type is not active whatever else the answer holds.
//
// [RFC 7662 §2.2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
// [RFC 6749 §3.3]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
// [RFC 6749 §5.1]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
func (r *Result) UnmarshalJSON(data []byte) error {
	var answer struct {
		Active    *bool  `json:"active"`
		TokenType string `json:"token_type"`
	}
	if err := json.Unmarshal(data, &answer); err != nil {
		return err
	}
	if answer.Active == nil || (*answer.Active && answer.TokenType == "") {
		return errors.New("an answer needs active, and an active one needs token_type")
	}
	if !*answer.Active || !strings.EqualFold(answer.TokenType, "Bearer") {
		*r = Result{}
		return nil
	}
	type plain Result
	var wire plain
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Issuer == "" || wire.Subject == "" || wire.ClientID == "" || wire.Expiry == 0 || wire.Audience == "" {
		return errors.New("an active answer needs iss, sub, client_id, exp and aud")
	}
	if wire.Scope != "" && slices.ContainsFunc(strings.Split(wire.Scope, " "), func(scope string) bool { return !oauthscope.ValidScope(scope) }) {
		return fmt.Errorf("scope %q is not space-separated scope tokens", wire.Scope)
	}
	_ = json.Unmarshal(data, &wire.Claims)
	maps.DeleteFunc(wire.Claims, tokenField)
	*r = Result(wire)
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
	fields["token_type"] = json.RawMessage(`"Bearer"`)
	return json.Marshal(fields)
}

// Check holds an active answer to the issuer the caller trusts, the exp and nbf of [RFC 7662 §2.2], and the audiences
// the caller accepts, of which [RFC 8707 §2.2] gives a token exactly one.
//
// [RFC 7662 §2.2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
// [RFC 8707 §2.2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2
func (r Result) Check(issuer string, now time.Time, audiences ...string) error {
	switch {
	case !r.Active:
		return errors.New("token is inactive")
	case r.Issuer != issuer:
		return fmt.Errorf("iss %q, want %q", r.Issuer, issuer)
	case r.Expiry <= now.Unix():
		return fmt.Errorf("exp %d is not in the future", r.Expiry)
	case r.NotBefore > now.Unix():
		return fmt.Errorf("nbf %d is in the future", r.NotBefore)
	case !slices.Contains(audiences, r.Audience):
		return fmt.Errorf("aud %q, want one of %q", r.Audience, audiences)
	}
	return nil
}

func tokenField(name string, _ json.RawMessage) bool { return slices.Contains(tokenFields, name) }
