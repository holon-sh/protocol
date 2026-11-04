package protocol

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"unicode/utf8"

	"github.com/holon-sh/protocol/oauthscope"
)

var ErrInvalidAccess = errors.New("invalid access configuration")

func (access *AppAccess) Rules() iter.Seq2[string, AccessRule] {
	return func(yield func(string, AccessRule) bool) {
		if access == nil || access.Server == nil || !yield("access.server", *access.Server) {
			return
		}
		for name, rule := range access.Tools {
			if !yield("access.tools["+name+"]", rule) {
				return
			}
		}
	}
}

func (rule AccessRule) Scopes() []string {
	if rule.OAuth == nil {
		return nil
	}
	return rule.OAuth.Scopes
}

func SessionScopes(mode string, apps []App) []string {
	var scopes []string
	if mode == ModeDevelopment {
		scopes = append(scopes, ScopeDevRead)
	}
	for _, app := range apps {
		for _, rule := range app.Access.Rules() {
			scopes = append(scopes, rule.Scopes()...)
		}
	}
	slices.Sort(scopes)
	return slices.Compact(scopes)
}

func ValidMCPName(name string) bool {
	return name != "" && len(name) <= 1024 && utf8.ValidString(name) && ValidInputValue(name)
}

func ValidateAccess(access *AppAccess) error {
	if access == nil || access.Server == nil {
		return errors.New("access.server must be explicit; use {} for public access")
	}
	if len(access.Callers) > 256 || len(access.Callers) > 0 && !ValidAppNames(access.Callers) {
		return errors.New("access.callers must contain at most 256 unique, valid app names")
	}
	if len(access.Tools) > 256 {
		return errors.New("access.tools must contain at most 256 entries")
	}
	for name := range access.Tools {
		if !ValidMCPName(name) {
			return errors.New("invalid access.tools name")
		}
	}
	for path, rule := range access.Rules() {
		if !oauthscope.ValidScopes(rule.Scopes()) {
			return fmt.Errorf("%s: oauth.scopes must contain unique OAuth scope tokens of at most 256 bytes", path)
		}
	}
	return nil
}

func AccessPolicy(apps []App, identityConfigured bool) error {
	for _, app := range apps {
		if err := ValidateAccess(app.Access); err != nil {
			return fmt.Errorf("%w: app %s: %w", ErrInvalidAccess, app.Name, err)
		}
		if !identityConfigured {
			for _, rule := range app.Access.Rules() {
				if rule.OAuth != nil {
					return fmt.Errorf("%w: app %s requires a configured identity provider", ErrInvalidAccess, app.Name)
				}
			}
		}
	}
	return nil
}
