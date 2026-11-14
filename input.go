package protocol

import (
	"regexp"
	"slices"
	"strings"

	"github.com/holon-sh/protocol/internal/model"
)

var envName = regexp.MustCompile(model.EnvNamePattern)

const (
	OTELServiceNameEnv          = model.OTELServiceNameEnv
	OTELResourceAttributesEnv   = model.OTELResourceAttributesEnv
	OTELExporterOTLPEndpointEnv = model.OTELExporterOTLPEndpointEnv
	OTELExporterOTLPProtocolEnv = model.OTELExporterOTLPProtocolEnv
)

// reservedEnv names the OpenTelemetry variables the controller sets in app containers, which carry the session key.
// The controller owns every HOLON_ variable too, and every <NAME>_MCP_URL, so an app's peer URLs are the platform's:
// an SDK sends the caller's context to them.
var reservedEnv = model.ReservedEnv

func ValidEnvName(value string) bool {
	return !slices.Contains(reservedEnv, value) && !strings.HasPrefix(value, model.ReservedEnvPrefix) && !strings.HasSuffix(value, DependencyEnvSuffix) &&
		len(value) <= model.MaxEnvNameBytes && envName.MatchString(value)
}

// ValidEnvTemplates reports whether each template sets a variable env does not declare, from inputs env declares.
func ValidEnvTemplates[I any](env map[string]I, templates map[string]Template) bool {
	for name, template := range templates {
		if _, declared := env[name]; declared || !ValidEnvName(name) || !validTemplate(env, template) {
			return false
		}
	}
	return true
}

// ValidArgs reports whether each argument is single-line text whose placeholders name inputs env declares.
func ValidArgs[I any](env map[string]I, args []Template) bool {
	return !slices.ContainsFunc(args, func(arg Template) bool { return !validTemplate(env, arg) })
}

// validTemplate reports whether a template is single-line text whose placeholders name inputs env declares.
func validTemplate[I any](env map[string]I, template Template) bool {
	_, complete := Expand(template, func(name string) (string, bool) {
		_, declared := env[name]
		return "", declared
	})
	return ValidInputValue(template) && complete
}

func (i Input) Kind() string {
	if i.IsSecret {
		return model.KindSecret
	}
	return model.KindConfig
}

func (i Input) Source(revision string) (*string, string) {
	if i.Value != nil {
		return i.Value, ""
	}
	if revision != "" {
		return nil, revision
	}
	return i.Default, ""
}
