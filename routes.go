package protocol

import (
	"cmp"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
)

var platformPaths = strings.Fields(PlatformPaths)

func WebPath(name string) string {
	if name == "" {
		return "/"
	}
	return "/" + name + "/"
}

func ParseWebPath(raw string) (string, bool) {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.RawPath != "" || u.EscapedPath() != u.Path || !strings.HasPrefix(u.Path, "/") ||
		strings.ContainsAny(u.Path, "\\\x00") || (u.Path != "/" && path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/")) {
		return "", false
	}
	return u.Path, u.Path != MCPPath
}

func BrowserPath(raw string) (string, bool) {
	webPath, valid := ParseWebPath(raw)
	first, _, _ := strings.Cut(strings.TrimPrefix(webPath, "/"), "/")
	return webPath, valid && !slices.Contains(platformPaths, "/"+first)
}

func AppBrowserMount(app App, mode string) string {
	mount := "/" + app.Name
	if mode == ModeProduction {
		return cmp.Or(app.Mount, mount)
	}
	return mount
}

func ValidateAppMounts(apps []App) error {
	seen := map[string]bool{}
	for _, app := range apps {
		if app.Remote != nil {
			if app.Mount != "" {
				return fmt.Errorf("app %s browser routing requires a local app", app.Name)
			}
			continue
		}
		mount := AppBrowserMount(app, ModeProduction)
		parsed, valid := BrowserPath(mount)
		if !valid || parsed != mount || mount != "/" && strings.HasSuffix(mount, "/") {
			return fmt.Errorf("app %s mount requires a canonical, non-platform browser path", app.Name)
		}
		if seen[mount] {
			return fmt.Errorf("app %s mount must be unique", app.Name)
		}
		seen[mount] = true
	}
	return nil
}
