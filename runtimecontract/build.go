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
	Frozen *Frozen `json:"frozen,omitempty"`
	Ran    *Ran    `json:"ran,omitempty"`
}

type Frozen struct {
	Architecture string  `json:"architecture"`
	Directory    string  `json:"directory"`
	Layers       []Layer `json:"layers"`
}

type Layer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	DiffID    string `json:"diffId"`
	Size      int64  `json:"size"`
}

type Ran struct {
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}
