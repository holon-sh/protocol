// Package model holds the rules of the runtime contract, which runtimecontract reads and spec/runtime/schema.json is
// written from.
package model

import (
	control "github.com/holon-sh/protocol/internal/model"
	"github.com/holon-sh/protocol/internal/rule"
)

// Issuer is the iss of every context Holon signs.
const Issuer = "urn:holon:identity"

// Context is a value of the context header as an SDK admits it: a compact JWS with base64url segments. Holon signs at
// most 16 KiB, but no SDK refuses a longer one.
var Context = rule.Text{Name: "ContextHeader", Pattern: `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`}

// Caller is a value of the caller header: <session>/<app>.
var Caller = rule.Text{Name: "CallerHeader", Pattern: `^[^/]+/[^/]+$`}

var nonEmpty = rule.Text{MinBytes: 1}

var json = rule.Map{Key: rule.Text{}, Value: rule.Opaque{}}

// Owner is the principal that started a lifecycle operation.
var Owner = control.Owner

var HookInvocation = rule.Object{Name: "HookInvocation", Members: []rule.Member{
	{Name: "operation", Rule: rule.Text{}, Required: true},
	{Name: "job", Rule: rule.Text{}, Required: true},
	{Name: "jobUID", Rule: rule.Text{}, Required: true},
	{Name: "app", Rule: rule.Text{}, Required: true},
	{Name: "step", Rule: rule.Integer{}, Required: true},
	{Name: "attempt", Rule: rule.Integer{}, Required: true},
	{Name: "deadline", Rule: rule.Text{}, Required: true, Description: "An RFC 3339 time."},
	{Name: "initiator", Rule: Owner},
}}

var Principal = rule.Object{Name: "Principal", Members: []rule.Member{
	{Name: "iss", Rule: nonEmpty, Required: true},
	{Name: "sub", Rule: nonEmpty, Required: true},
	{Name: "scope", Rule: rule.Text{}, Description: "Space-separated scope tokens."},
	{Name: "client_id", Rule: nonEmpty, Required: true},
	{Name: "act", Rule: json, Description: "The delegation claim of RFC 8693 §4.1."},
	{Name: "claims", Rule: json, Description: "The identity provider's other claims about the person."},
}}

var Claims = rule.Object{Name: "Claims", Members: []rule.Member{
	{Name: "iss", Rule: rule.Enumeration{Values: []string{Issuer}}, Required: true},
	{Name: "sub", Rule: nonEmpty, Required: true, Description: "The session's UID."},
	{Name: "aud", Rule: rule.List{Item: nonEmpty, MinItems: 1, MaxItems: 1}, Required: true},
	{Name: "exp", Rule: rule.Integer{}, Required: true},
	{Name: "iat", Rule: rule.Integer{}, Required: true},
	{Name: "principal", Rule: Principal, Description: "Absent when no person or client is signed in."},
	{Name: "flowId", Rule: nonEmpty, Required: true},
	{Name: "hook", Rule: HookInvocation, Description: "Present for an authorized lifecycle hook invocation."},
}}
