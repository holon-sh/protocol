package protocol

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/holon-sh/protocol/internal/model"
)

const (
	sha256Digest   = model.SHA256Digest
	repositoryName = model.RepositoryName
	tag            = model.Tag
	registryHost   = model.RegistryHost
)

var (
	digestPattern     = regexp.MustCompile(`^` + sha256Digest + `$`)
	repositoryPattern = regexp.MustCompile(`^` + repositoryName + `$`)
	imagePattern      = regexp.MustCompile(`^(?:(` + registryHost + `)/)?(` + repositoryName + `)(?::` + tag + `)?(?:@(` + sha256Digest + `))?$`)
)

func ValidDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func ValidRepository(value string) bool {
	return len(value) <= 255 && repositoryPattern.MatchString(value)
}

func ValidRegistryHost(value string) bool {
	if len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse("//" + value)
	return err == nil && parsed.Host == value && parsed.Hostname() != ""
}

func ValidImageRepositoryPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	host, repository, _ := strings.Cut(prefix, "/")
	domain, path, _, ok := parseImage(prefix + "/holon-validation")
	return ok && domain == host && path == repository+"/holon-validation"
}

func IsValidDigestImage(image string) bool {
	_, _, digest, ok := parseImage(image)
	return ok && digest != ""
}

func parseImage(image string) (domain, path, digest string, ok bool) {
	match := imagePattern.FindStringSubmatch(image)
	if match == nil || len(match[2]) > 255 {
		return "", "", "", false
	}
	domain, path, digest = match[1], match[2], match[3]
	switch domain {
	case "localhost":
		return domain, path, digest, true
	case "docker.io":
		return domain, path, digest, strings.Contains(path, "/")
	case "", "index.docker.io":
		return domain, path, digest, false
	}
	return domain, path, digest, strings.ContainsAny(domain, ".:") || strings.ToLower(domain) != domain
}

func ValidBuildArchitectures(architectures []string) bool {
	return (len(architectures) < 2 || len(architectures) == 2 && architectures[0] != architectures[1]) &&
		!slices.ContainsFunc(architectures, func(architecture string) bool {
			return !slices.Contains(model.Architectures, architecture)
		})
}
