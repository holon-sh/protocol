package runtimecontract

const (
	BuildPath        = "/.holon/build"
	BuildFile        = ".holon/build.json"
	BuildTokenHeader = "X-Holon-Build-Token"
)

type Build struct {
	Layer bool     `json:"layer,omitempty"`
	Run   []string `json:"run,omitempty"`
}

type BuildReply struct {
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
	Stdout string `json:"stdout,omitempty"`
	Layer  *Layer `json:"layer,omitempty"`
}

type Layer struct {
	Digest       string `json:"digest"`
	DiffID       string `json:"diffId"`
	Size         int64  `json:"size"`
	Architecture string `json:"architecture"`
}
