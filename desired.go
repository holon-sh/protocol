package protocol

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

func WritableApps(apps []App) []App {
	result := slices.Clone(apps)
	for i := range result {
		app := &result[i]
		app.Release = nil
		app.Applied = nil
		app.Requires = slices.Clone(app.Requires)
		slices.Sort(app.Requires)
	}
	slices.SortFunc(result, func(a, b App) int { return strings.Compare(a.Name, b.Name) })
	return result
}

func ChangedApps(before, after []App) []string {
	prior := make(map[string]string, len(before))
	for _, app := range WritableApps(before) {
		encoded, _ := json.Marshal(app)
		prior[app.Name] = string(encoded)
	}
	var changed []string
	for _, app := range WritableApps(after) {
		encoded, _ := json.Marshal(app)
		if prior[app.Name] != string(encoded) {
			changed = append(changed, app.Name)
		}
		delete(prior, app.Name)
	}
	changed = slices.AppendSeq(changed, maps.Keys(prior))
	slices.Sort(changed)
	return changed
}
