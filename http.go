package protocol

const (
	SchemeHTTPS         = "https"
	HTTPSPrefix         = SchemeHTTPS + "://"
	APIPathSessions     = "/sessions"
	MCPPathPrefix       = "/mcp/"
	MCPPath             = "/mcp"
	HeaderAuthorization = "Authorization"
	HeaderContentType   = "Content-Type"
	MIMEApplicationJSON = "application/json"
	MIMETextPlain       = "text/plain; charset=utf-8"
	BearerScheme        = "Bearer"
	BearerPrefix        = BearerScheme + " "
	UploadUsername      = "holon-upload"
)
