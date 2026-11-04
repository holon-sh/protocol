package protocol

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// sha256Digest is an [OCI image spec] SHA-256 digest.
//
// [OCI image spec]: https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md#sha-256
const sha256Digest = `sha256:[a-f0-9]{64}`

// repositoryName is the [OCI distribution spec] <name> grammar.
//
// [OCI distribution spec]: https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests
const repositoryName = `[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*`

// tag is the [OCI distribution spec] <reference> grammar for a tag.
//
// [OCI distribution spec]: https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests
const tag = `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`

// registryHost is an [RFC 1123 §2.1] host name or an [RFC 3986 §3.2.2] IP-literal, with an optional port.
//
// [RFC 1123 §2.1]: https://www.rfc-editor.org/rfc/rfc1123#section-2.1
// [RFC 3986 §3.2.2]: https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2
const registryHost = `(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?`

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
			return !slices.Contains([]string{"amd64", "arm64"}, architecture)
		})
}
