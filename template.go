package protocol

import "regexp"

// A template is text in which each {NAME} stands for the value of the input NAME. It follows the MCP Registry, whose
// input values substitute their variables the same way.
var placeholder = regexp.MustCompile(`\{([^{}]+)\}`)

// TemplateInputs returns the names a template's placeholders refer to.
func TemplateInputs(template string) []string {
	var names []string
	for _, match := range placeholder.FindAllStringSubmatch(template, -1) {
		names = append(names, match[1])
	}
	return names
}

// Expand replaces each placeholder with lookup's value for its input. A templated value is absent unless every input
// it names has a value.
func Expand(template string, lookup func(string) (string, bool)) (string, bool) {
	complete := true
	expanded := placeholder.ReplaceAllStringFunc(template, func(match string) string {
		value, present := lookup(match[1 : len(match)-1])
		complete = complete && present
		return value
	})
	return expanded, complete
}
