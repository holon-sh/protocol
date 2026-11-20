package protocol

import "encoding/json"

const (
	ToolCreateSession      = "create_session"
	ToolGetSession         = "get_session"
	ToolListSessions       = "list_sessions"
	ToolUpdateSession      = "update_session"
	ToolDeleteSession      = "delete_session"
	ToolRenewSession       = "renew_session"
	ToolGetLogs            = "get_logs"
	ToolGetAppContract     = "get_app_contract"
	ToolAuthorizeLifecycle = "authorize_lifecycle"
	ToolRetryLifecycle     = "retry_lifecycle"
	ToolUploadGrant        = "issue_upload_grant"
	ToolSetValue           = "set_value"
	ToolDeleteValue        = "delete_value"
	ToolListValues         = "list_values"
	ToolGetEgress          = "get_egress"
	ToolSetEgress          = "set_egress"
	ToolGetIdentity        = "get_identity"
)

// MCPCallEvent is the event.name of the completion record logged for each MCP call, sampled or not.
const MCPCallEvent = "holon.mcp.call"

type SessionRequest struct {
	Session string `json:"session"`
}

// GetSessionRequest reads a session; with a Revision the server first waits for the session to move past it.
type GetSessionRequest struct {
	SessionRequest

	Revision string `json:"revision,omitempty"`
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

// SessionLogs is a bounded log snapshot: at most the request's limit of records, whose bodies total at most 64 KiB.
type SessionLogs struct {
	Environment string      `json:"environment,omitempty"`
	Session     string      `json:"session"`
	App         string      `json:"app"`
	Records     []LogRecord `json:"records"`
}

// LogRecord is one collected log record.
type LogRecord struct {
	Time       string            `description:"RFC 3339 time with nanoseconds."                                                    json:"time"`
	Severity   string            `description:"OTLP severity text."                                                                json:"severity,omitempty"`
	App        string            `description:"The record's service.name: an app or a platform service."                           json:"app,omitempty"`
	Body       string            `json:"body"`
	TraceID    string            `json:"traceId,omitempty"`
	Attributes map[string]string `description:"The record's other attributes, named as Loki labels, such as holon_lifecycle_hook." json:"attributes,omitempty"`
}

// Line renders the record as GET /sessions/{id}/logs streams it: "time severity app body trace_id=…".
func (r LogRecord) Line() string {
	line := r.Time + " " + r.Severity + " " + r.App + " " + r.Body
	if r.TraceID != "" {
		line += " trace_id=" + r.TraceID
	}
	return line + "\n"
}

// Caller is the get_identity reply. Identity is present and null when identity is disabled.
type Caller struct {
	Identity     *CallerIdentity    `json:"identity"`
	Capabilities CallerCapabilities `json:"capabilities"`
}

type CallerCapabilities struct {
	Telemetry bool `json:"telemetry"`
}

// CallerIdentity describes a verified caller and its granted scopes.
type CallerIdentity struct {
	Act     json.RawMessage `json:"act,omitempty"`
	Issuer  string          `json:"issuer"`
	Subject string          `json:"subject"`
	Scopes  []string        `json:"scopes"`
	Profile *CallerProfile  `json:"profile,omitempty"`
}

// CallerProfile is the small set of verified token claims displayed by the console.
type CallerProfile struct {
	Name             string `json:"name,omitempty"`
	Email            string `json:"email,omitempty"`
	EmailVerified    bool   `json:"emailVerified,omitempty"`
	IdentityProvider string `json:"identityProvider,omitempty"`
}

// ReloadAppResult is how long the API waited for the app to restart from new source, and the end of what it printed.
type ReloadAppResult struct {
	ElapsedSeconds float64 `json:"elapsedSeconds"`
	Output         string  `description:"The end of what installing and building the app printed." json:"output,omitempty"`
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

type UpdateSessionRequest struct {
	SessionRequest
	WritePrecondition

	Desired AppsRequest `json:"desired"`
	Remove  []string    `json:"remove,omitempty"`
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
	Allow Egress `json:"allow,omitzero"`
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

type DeleteSessionResult struct {
	Deleted bool             `json:"deleted"`
	Session *SessionResponse `json:"session,omitempty"`
}

type Sessions struct {
	Items []SessionResponse `json:"items"`
}

// MaxTTLSeconds is the longest AppsRequest.TTLSeconds, a detached session's lifetime.
const MaxTTLSeconds = 7 * 24 * 60 * 60

type AppsRequest struct {
	// Session, on create_session, names a session to create, or the caller's development session to update in place.
	// It must be a ValidSessionName; without it the installation generates a name.
	Session    string    `json:"session,omitempty"`
	RequestID  string    `json:"requestId,omitempty"`
	TTLSeconds *int64    `json:"ttlSeconds,omitempty"`
	Apps       []App     `json:"apps"`
	Revision   *Revision `json:"revision,omitempty"`
}

func (input *AppsRequest) UnmarshalJSON(data []byte) error {
	type plain AppsRequest
	return DecodeJSONFields(data, (*plain)(input), "apps")
}

// Revision is the Git commit a deploy's apps were built from.
type Revision struct {
	Commit string `json:"commit"`
	// Dirty reports that the deployed files differed from Commit.
	Dirty bool `json:"dirty,omitempty"`
}

// VariableRequest names a config value or secret by the apps it is set for, in development (for every session, or one)
// or in production. Apps that share a value are linked: each receives it, and setting it for all of them changes it once.
type VariableRequest struct {
	Session  string   `json:"session,omitempty"`
	Apps     []string `json:"apps"`
	Kind     string   `json:"kind"`
	Variable string   `json:"variable"`
}

// SetValueRequest sets one value for exactly the apps it names, linking them. Naming the revision of a listed value
// replaces it: apps linked to it but not named are unlinked, and without a value the apps get its value. The request
// fails if no app is linked to that revision any more.
type SetValueRequest struct {
	VariableRequest

	Revision string  `json:"revision,omitempty"`
	Value    *string `json:"value,omitempty"`
	Note     string  `json:"note,omitempty"`
}

// ConfigValue is a value and the apps linked to it. Its revision names it in a SetValueRequest that replaces it.
type ConfigValue struct {
	Session   string   `json:"session,omitempty"`
	Apps      []string `json:"apps"`
	Kind      string   `json:"kind"`
	Variable  string   `json:"variable"`
	Revision  string   `json:"revision"`
	Value     *string  `json:"value,omitempty"`
	Note      string   `json:"note,omitempty"`
	UpdatedAt string   `json:"updatedAt"`
	UpdatedBy string   `json:"updatedBy,omitempty"`
}

type ConfigValues struct {
	Values []ConfigValue `json:"values"`
}

// UploadRequest asks for repository upload authority for named apps.
type UploadRequest struct {
	Apps []string `json:"apps"`
}

// UploadGrant authorizes image uploads. Treat the grant as a credential until expiry.
type UploadGrant struct {
	Grant        string            `json:"grant"`
	Registry     string            `json:"registry"`
	Repositories map[string]string `json:"repositories"`
	ExpiresAt    string            `json:"expiresAt"`
}

const BaseRepository = "development"
