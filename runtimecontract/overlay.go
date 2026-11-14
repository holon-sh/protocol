package runtimecontract

import (
	"net/url"

	"github.com/holon-sh/protocol"
)

const (
	ReloadPath       = "/.holon/reload"
	OverlayFileEnv   = "HOLON_OVERLAY_FILE"
	OverlayMediaType = "application/vnd.holon.source-overlay.v0.tar+zstd"
	InstallFile      = ".holon/install"
	PrepareFile      = ".holon/prepare"
	StartFile        = ".holon/start"
)

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
