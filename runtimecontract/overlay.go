package runtimecontract

import (
	"net/url"

	"github.com/holon-sh/protocol"
)

// A source overlay is a development app's source as one zstd-compressed tar, with StartFile, the script that installs,
// builds and serves it. holon-api posts a save's overlay to ReloadPath on the app, and the platform records the latest
// one in the file OverlayFileEnv names, which a new container starts from.
const (
	ReloadPath       = "/.holon/reload"
	OverlayFileEnv   = "HOLON_OVERLAY_FILE"
	OverlayMediaType = "application/vnd.holon.source-overlay.v0.tar+zstd"
	StartFile        = ".holon/start"
)

// ReloadFailure is the reply to a reload that did not start the app.
type ReloadFailure struct {
	Error string `json:"error"`
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
