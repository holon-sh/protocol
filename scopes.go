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

func HostScopes(host Host) (read, write string) {
	if host == AdminHost {
		return ScopeProdRead, ScopeProdWrite
	}
	return ScopeDevRead, ScopeDevWrite
}

func ControlScopes(host Host) []string {
	switch host {
	case AdminHost, ConsoleHost:
		return SystemScopes()
	case DevHost:
		return []string{ScopeDevRead, ScopeDevWrite}
	}
	return nil
}
