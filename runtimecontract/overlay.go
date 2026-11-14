package runtimecontract

import (
	"net/url"
)

// A source overlay is a development app's source as one zstd-compressed tar, with two scripts: PrepareFile installs and
// builds what the app needs, and StartFile serves it. What PrepareFile prints goes only to a reload's reply; what
// StartFile prints is the app's log.
const (
	ReloadPath       = "/.holon/reload"
	OverlayFileEnv   = "HOLON_OVERLAY_FILE"
	OverlayMediaType = "application/vnd.holon.source-overlay.v0.tar+zstd"
	PrepareFile      = ".holon/prepare"
	StartFile        = ".holon/start"
)

// ReloadReply is the body of a reload's reply: the end of what PrepareFile printed, and why the app did not start when
// the reload fails.
type ReloadReply struct {
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}

type OverlayRecord struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Token      string `json:"token"`
}

func (r OverlayRecord) Location() *url.URL {
	base, err := url.Parse(r.Registry)
	if err != nil || base.Host == "" || base.Scheme != "http" && base.Scheme != "https" || r.Repository == "" || r.Tag == "" ||
		r.Token == "" {
		return nil
	}
	return base.JoinPath("v2", r.Repository)
}
