package protocol

import (
	"regexp"
	"slices"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const (
	OTELServiceNameEnv          = "OTEL_SERVICE_NAME"
	OTELResourceAttributesEnv   = "OTEL_RESOURCE_ATTRIBUTES"
	OTELExporterOTLPEndpointEnv = "OTEL_EXPORTER_OTLP_ENDPOINT"
	OTELExporterOTLPProtocolEnv = "OTEL_EXPORTER_OTLP_PROTOCOL"
)

// reservedEnv names the variables the controller sets in app containers, including the OpenTelemetry settings that carry the session key.
var reservedEnv = []string{
	RuntimeConfigEnv, "HOLON_HOOK_CONFIG",
	OTELServiceNameEnv, OTELResourceAttributesEnv, OTELExporterOTLPEndpointEnv, OTELExporterOTLPProtocolEnv,
}

func ValidEnvName(value string) bool {
	return !slices.Contains(reservedEnv, value) && len(value) <= 128 && envName.MatchString(value)
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
		return "secret"
	}
	return "config"
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
