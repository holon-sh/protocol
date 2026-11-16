package runtimecontract

const (
	BuildPath        = "/.holon/build"
	BuildFile        = ".holon/build.json"
	BuildTokenHeader = "X-Holon-Build-Token"
)

type Build struct {
	Freeze *Freeze  `json:"freeze,omitempty"`
	Run    []string `json:"run,omitempty"`
}

type Freeze struct {
	Dependencies []string `json:"dependencies,omitempty"`
	Omit         []string `json:"omit,omitempty"`
}

type BuildReply struct {
	Error  string  `json:"error,omitempty"`
	Output string  `json:"output,omitempty"`
	Stdout string  `json:"stdout,omitempty"`
	Frozen *Frozen `json:"frozen,omitempty"`
}

type Frozen struct {
	Architecture string  `json:"architecture"`
	Layers       []Layer `json:"layers"`
}

type Layer struct {
	Digest string `json:"digest"`
	DiffID string `json:"diffId"`
	Size   int64  `json:"size"`
}
