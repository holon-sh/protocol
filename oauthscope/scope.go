package oauthscope

import (
	"regexp"
	"slices"
)

func ValidScopes(scopes []string) bool {
	return !slices.ContainsFunc(scopes, func(scope string) bool { return !ValidScope(scope) }) &&
		len(slices.Compact(slices.Sorted(slices.Values(scopes)))) == len(scopes)
}

const ScopePattern = `^[\x21\x23-\x5B\x5D-\x7E]+$`

var scopePattern = regexp.MustCompile(ScopePattern)

// ValidScope reports whether scope is an [RFC 6749 §3.3] scope-token of at most 256 bytes.
//
// [RFC 6749 §3.3]: https://www.rfc-editor.org/rfc/rfc6749#section-3.3
func ValidScope(scope string) bool {
	return len(scope) <= 256 && scopePattern.MatchString(scope)
}
