package runtimecontract

import (
	"net/url"

	"github.com/holon-sh/protocol"
)

// A source overlay is a development app's source as one zstd-compressed tar, with three scripts run in turn.
// InstallFile installs what the app depends on; a container skips it when the last InstallFile it ran had the same
// bytes and succeeded, so the CLI makes it differ whenever the files it installs from change. PrepareFile builds what
// the app serves, every time the app starts, and StartFile serves it. What InstallFile and PrepareFile print goes only to a
// reload's reply; what StartFile prints is the app's log. holon-api posts a save's overlay to ReloadPath on the app,
// and the platform records the latest one in the file OverlayFileEnv names, which a new container starts from.
const (
	ReloadPath       = "/.holon/reload"
	OverlayFileEnv   = "HOLON_OVERLAY_FILE"
	OverlayMediaType = "application/vnd.holon.source-overlay.v0.tar+zstd"
	InstallFile      = ".holon/install"
	PrepareFile      = ".holon/prepare"
	StartFile        = ".holon/start"
)

// ReloadReply is the body of a reload's reply: the end of what InstallFile and PrepareFile printed, and why the app did
// not start when the reload fails.
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
