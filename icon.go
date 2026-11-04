package protocol

// Icon is the [MCP icon] object shared by server descriptors and app declarations.
//
// [MCP icon]: https://modelcontextprotocol.io/specification/2025-11-25/basic/index#icons
type Icon struct {
	Source   string   `json:"src"`
	MIMEType string   `json:"mimeType,omitempty"`
	Sizes    []string `json:"sizes,omitempty"`
	Theme    string   `json:"theme,omitempty"`
}
