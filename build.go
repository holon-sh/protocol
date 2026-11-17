package protocol

import (
	"errors"
	"fmt"
)

type BuildRuntime struct {
	Icons        []Icon              `json:"icons,omitempty"`
	Port         int32               `json:"port"`
	Args         []Template          `json:"args,omitempty"`
	Env          map[string]Input    `json:"env,omitempty"`
	EnvTemplates map[string]Template `json:"envTemplates,omitempty"`
	Requires     []string            `json:"requires,omitempty"`
	Egress       Egress              `json:"egress,omitzero"`
	// Remote is set by an OpenAPI import; such a build has no image.
	Remote *Remote `json:"remote,omitempty"`
}

type BuildRecord struct {
	SchemaVersion      int          `json:"schemaVersion"`
	AppName            string       `json:"appName"`
	ServerName         string       `json:"serverName,omitempty"`
	ServerVersion      string       `json:"serverVersion,omitempty"`
	Title              string       `json:"title,omitempty"`
	Description        string       `json:"description,omitempty"`
	Runtime            BuildRuntime `json:"runtime"`
	UnsupportedReasons []string     `json:"unsupportedReasons"`
}

func (r BuildRecord) Validate() error {
	remote := r.Runtime.Remote
	if r.SchemaVersion != 1 || !ValidAppName(r.AppName) || len(r.Runtime.Env) > 64 || remote == nil && !ValidPort(int(r.Runtime.Port)) {
		return errors.New("unsupported or invalid app build metadata")
	}
	for name, input := range r.Runtime.Env {
		if !ValidEnvName(name) {
			return fmt.Errorf("invalid input %q", name)
		}
		if err := input.Validate(); err != nil {
			return err
		}
	}
	if !ValidArgs(r.Runtime.Env, r.Runtime.Args) || !ValidEnvTemplates(r.Runtime.Env, r.Runtime.EnvTemplates) {
		return errors.New("app build args and environment templates must name declared inputs")
	}
	if remote == nil {
		return nil
	}
	if remote.OpenAPI == "" || r.Runtime.Port != 0 || r.Runtime.Args != nil || r.Runtime.EnvTemplates != nil {
		return errors.New("a remote app build serves an OpenAPI model and has no port, args or environment templates")
	}
	return remote.Validate(r.Runtime.Env)
}
