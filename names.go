package protocol

import (
	"slices"

	"github.com/holon-sh/protocol/internal/model"
)

const (
	ModeDevelopment = "development"
	ModeProduction  = "production"
	ProductionName  = "production"
)

const PlatformPaths = model.PlatformPaths

func ReservedAppNames() []string {
	return slices.Clone(model.ReservedAppNames)
}

func ValidAppName(value string) bool {
	return len(value) <= model.MaxAppNameBytes && ValidDNSLabel(value) && !slices.Contains(model.ReservedAppNames, value)
}

func ValidAppNames(names []string) bool {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] || !ValidAppName(name) {
			return false
		}
		seen[name] = true
	}
	return true
}
