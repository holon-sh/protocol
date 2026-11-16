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
}

type BuildReply struct {
	ReloadReply
	Image string `json:"image,omitempty"`
	Ran   *Ran   `json:"ran,omitempty"`
}

type Ran struct {
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}
