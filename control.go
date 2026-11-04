package protocol

const (
	ToolCreateSession      = "create_session"
	ToolGetSession         = "get_session"
	ToolUpdateSession      = "update_session"
	ToolDeleteSession      = "delete_session"
	ToolRenewSession       = "renew_session"
	ToolAuthorizeLifecycle = "authorize_lifecycle"
	ToolRetryLifecycle     = "retry_lifecycle"
	ToolUploadGrant        = "issue_upload_grant"
	ToolSetValue           = "set_value"
	ToolDeleteValue        = "delete_value"
	ToolListValues         = "list_values"
	ToolGetEgress          = "get_egress"
	ToolSetEgress          = "set_egress"
)

// MCPCallEvent is the event.name of the completion record logged for each MCP call, sampled or not.
const MCPCallEvent = "holon.mcp.call"

type SessionRequest struct {
	Session string `json:"session"`
}

type WritePrecondition struct {
	ExpectedRevision string `json:"expectedRevision,omitempty"`
	CreateOnly       bool   `json:"createOnly,omitempty"`
}

type DeleteSessionRequest struct {
	SessionRequest

	ExpectedRevision string `json:"expectedRevision"`
	SkipHooks        bool   `json:"skipHooks,omitempty"`
}

type AuthorizeLifecycleRequest struct {
	SessionRequest

	Operation   string `json:"operation"`
	AccessToken string `json:"accessToken,omitempty"`
}

type RetryLifecycleRequest struct {
	SessionRequest

	Operation        string `json:"operation"`
	ExpectedRevision string `json:"expectedRevision"`
}

// AppRequest selects a deployment and optionally one of its apps.
type AppRequest struct {
	SessionRequest

	Environment string `json:"environment,omitempty"`
	App         string `json:"app,omitempty"`
}

// SessionLogsRequest selects collected records: app stdout and stderr, lifecycle hook output and MCP completion
// records. An empty App means every app.
type SessionLogsRequest struct {
	AppRequest

	Operation string `json:"operation,omitempty"` // lifecycle operation ID
	Hook      string `json:"hook,omitempty"`      // lifecycle hook key
	Attempt   *int64 `json:"attempt,omitempty"`   // lifecycle attempt, from 1
	Event     string `json:"event,omitempty"`     // record event name, such as MCPCallEvent
	Tool      string `json:"tool,omitempty"`      // a completion record's MCP tool
	Status    string `json:"status,omitempty"`    // a completion record's outcome: ok or error
	Since     string `json:"since,omitempty"`     // duration or RFC 3339; default 15m
	TraceID   string `json:"traceId,omitempty"`   // records for one trace
	Text      string `json:"text,omitempty"`      // substring filter
}

// ErrorResponse is the control-plane error envelope.
type ErrorResponse struct {
	Error Error `json:"error"`
}

// Error contains a stable machine-readable code and a human-readable message.
type Error struct {
	LoginURL string `json:"loginUrl,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

type UpdateSessionRequestFor[Desired any] struct {
	SessionRequest
	WritePrecondition

	Desired Desired  `json:"desired"`
	Remove  []string `description:"App names to delete from the session." json:"remove,omitempty"`
}

type EgressRequest struct {
	App string `json:"app"`
}

type SetEgressRequest struct {
	EgressRequest
	WritePrecondition

	Policy AppEgressPolicy `json:"policy"`
}

// AppEgressPolicy is the installation's egress ceiling for one app.
type AppEgressPolicy struct {
	Allow Egress `description:"Omitted removes this app's ceiling; destinations cap what the app may reach, together with the installation-wide ceiling." json:"allow,omitzero"`
}

// EgressStatus reports asynchronous policy reconciliation and rollout.
type EgressStatus struct {
	Reconciled      bool   `json:"reconciled"`
	RolloutComplete bool   `json:"rolloutComplete"`
	Targets         int    `json:"targets"`
	Pending         int    `json:"pending"`
	Degraded        bool   `json:"degraded"`
	Message         string `json:"message,omitempty"`
}

// EgressResponse combines the declared policy with its observed status.
type EgressResponse struct {
	AppEgressPolicy

	Revision string       `json:"revision"`
	App      string       `json:"app"`
	Status   EgressStatus `json:"status"`
}

type DeleteSessionResultFor[Session any] struct {
	Deleted bool     `json:"deleted"`
	Session *Session `json:"session,omitempty"`
}

type AppsRequestFor[A any] struct {
	RequestID  string `json:"requestId,omitempty"`
	TTLSeconds *int64 `json:"ttlSeconds,omitempty" maximum:"86400" minimum:"1"`
	Apps       []A    `json:"apps"                 minItems:"1"    nullable:"false" required:"true"`
}

func (input *AppsRequestFor[A]) UnmarshalJSON(data []byte) error {
	type plain AppsRequestFor[A]
	return DecodeJSONFields(data, (*plain)(input), "apps")
}

type VariableRequest struct {
	Session  string `json:"session,omitempty"`
	Kind     string `json:"kind"`
	Variable string `json:"variable"`
}

type SetValueRequest struct {
	VariableRequest

	Value string `json:"value"`
	Note  string `json:"note,omitempty" maxLength:"256"`
}

type ConfigValue struct {
	Session   string  `json:"session,omitempty"`
	Kind      string  `json:"kind"`
	Variable  string  `json:"variable"`
	Value     *string `json:"value,omitempty"`
	Note      string  `json:"note,omitempty"`
	UpdatedAt string  `json:"updatedAt"`
	UpdatedBy string  `json:"updatedBy,omitempty"`
}

type ConfigValues struct {
	Values []ConfigValue `json:"values" nullable:"false" required:"true"`
}

// UploadRequest asks for repository upload authority for named apps.
type UploadRequest struct {
	Apps []string `json:"apps" minItems:"1" nullable:"false" required:"true"`
}

// UploadGrant authorizes image uploads. Treat the grant as a credential until expiry.
type UploadGrant struct {
	Grant        string            `json:"grant"`
	Registry     string            `json:"registry"`
	Repositories map[string]string `json:"repositories"`
	ExpiresAt    string            `json:"expiresAt"`
}
