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
	if r.SchemaVersion != 1 || !ValidAppName(r.AppName) || !ValidPort(int(r.Runtime.Port)) || len(r.Runtime.Env) > 64 {
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
	return nil
}
