package runtimecontract

import (
	"net/url"
)

// A source overlay is a development app's source as one zstd-compressed tar, with two scripts: PrepareFile installs and
// builds what the app needs, and StartFile serves it. What PrepareFile prints goes only to a reload's reply; what
// StartFile prints is the app's log. holon-api posts a save's overlay to ReloadPath on the app. holon dev also pushes it
// to the app's repository as an artifact whose one layer is the overlay, and moves OverlayTag to it; a new container
// starts from the overlay that tag names, in the repository the file OverlayFileEnv names.
const (
	ReloadPath       = "/.holon/reload"
	OverlayFileEnv   = "HOLON_OVERLAY_FILE"
	OverlayMediaType = "application/vnd.holon.source-overlay.v0.tar+zstd"
	OverlayTag       = "source"
	PrepareFile      = ".holon/prepare"
	StartFile        = ".holon/start"
)

// ReloadReply is the body of a reload's reply: the end of what PrepareFile printed, and why the app did not start when
// the reload fails.
type ReloadReply struct {
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}

// OverlayRecord is where the platform keeps an app's overlays: a repository the token may read from the registry.
type OverlayRecord struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Token      string `json:"token"`
}

// Location is the URL of a well-formed record's repository in the registry's API, and nil for a malformed record.
func (r OverlayRecord) Location() *url.URL {
	base, err := url.Parse(r.Registry)
	if err != nil || base.Host == "" || base.Scheme != "http" && base.Scheme != "https" || r.Repository == "" || r.Token == "" {
		return nil
	}
	return base.JoinPath("v2", r.Repository)
}
