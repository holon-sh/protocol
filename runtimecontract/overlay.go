package runtimecontract

import (
	"net/url"
)

const (
	ReloadPath       = "/.holon/reload"
	OverlayFileEnv   = "HOLON_OVERLAY_FILE"
	OverlayMediaType = "application/vnd.holon.source-overlay.v0.tar+zstd"
	PlanFile         = ".holon/plan.json"
)

type Plan struct {
	Install Install    `json:"install"`
	Prepare [][]string `json:"prepare,omitempty"`
	Start   []string   `json:"start"`
}

type Install struct {
	Inputs   string     `json:"inputs"`
	Commands [][]string `json:"commands,omitempty"`
}

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
