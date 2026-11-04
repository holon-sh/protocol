package protocol

const (
	ScopeDevRead   = "system:dev:read"
	ScopeDevWrite  = "system:dev:write"
	ScopeProdRead  = "system:prod:read"
	ScopeProdWrite = "system:prod:write"
)

func SystemScopes() []string {
	return []string{ScopeDevRead, ScopeDevWrite, ScopeProdRead, ScopeProdWrite}
}

func PlaneScopes(plane Plane) (read, write string) {
	if plane == AdminPlane {
		return ScopeProdRead, ScopeProdWrite
	}
	return ScopeDevRead, ScopeDevWrite
}

func ControlScopes(plane Plane) []string {
	if plane == AdminPlane {
		return SystemScopes()
	}
	return []string{ScopeDevRead, ScopeDevWrite}
}
