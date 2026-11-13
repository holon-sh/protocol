package runtimecontract

import (
	"net/url"

	"github.com/holon-sh/protocol"
)

// A source overlay is a development app's source as one zstd-compressed tar. PrepareFile installs dependencies;
// StartFile serves the app. An optional BuildFile builds frontend files independent of server imports beside startup.
// Builds required by the server belong in PrepareFile. A reload succeeds only after
// both the build and startup succeed. PrepareFile and BuildFile output goes to the reload reply; StartFile output
// is the app's log. holon-api posts source to ReloadPath and records the latest overlay through OverlayFileEnv.
const (
	ReloadPath       = "/.holon/reload"
	OverlayFileEnv   = "HOLON_OVERLAY_FILE"
	OverlayMediaType = "application/vnd.holon.source-overlay.v0.tar+zstd"
	PrepareFile      = ".holon/prepare"
	BuildFile        = ".holon/build"
	StartFile        = ".holon/start"
	// ConcurrentBuildEnv is set to "1" for preparation by a supervisor that runs BuildFile itself. A prepare script
	// that carries BuildFile must run it synchronously when this variable is absent, so older supervisors remain safe.
	ConcurrentBuildEnv = "HOLON_CONCURRENT_BUILD"
)

// ReloadReply carries the end of preparation and build output, and why a reload failed.
type ReloadReply struct {
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}

// OverlayRecord is where the platform keeps an app's latest overlay: a blob the token may read from the registry.
type OverlayRecord struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Token      string `json:"token"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
}

// Blob is the URL of a well-formed record's overlay, and nil for a malformed record.
func (r OverlayRecord) Blob() *url.URL {
	base, err := url.Parse(r.Registry)
	if err != nil || base.Host == "" || base.Scheme != "http" && base.Scheme != "https" || r.Repository == "" ||
		r.Token == "" || !protocol.ValidDigest(r.Digest) || r.MediaType != OverlayMediaType {
		return nil
	}
	return base.JoinPath("v2", r.Repository, "blobs", r.Digest)
}
