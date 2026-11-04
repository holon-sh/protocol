# protocol

`github.com/holon-sh/protocol` holds the contracts shared by the Holon server, the Cloud CLI, the application runtime, the identity adapter and the Cloud provisioner: the wire and app declarations, the hook and app-build artifact formats, the runtime context, the OAuth scope syntax and the identity registration API. It depends on the Go standard library alone, so a consumer takes on no dependency graph by importing it. Releases are tagged on `main` and every consumer pins one.

```go
import "github.com/holon-sh/protocol/oauthscope"

ok := oauthscope.ValidScopes([]string{"app:chat:read", "app:chat:write"})
```
