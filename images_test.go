package protocol_test

import (
	"strings"
	"testing"

	"github.com/holon-sh/protocol"
)

func TestImageReferenceContracts(t *testing.T) {
	hex := strings.Repeat("0123456789abcdef", 4)
	for _, tc := range []struct {
		name           string
		valid          func(string) bool
		accept, reject []string
	}{
		{
			"digest", protocol.ValidDigest,
			[]string{"sha256:" + hex},
			[]string{"sha256:" + strings.ToUpper(hex), "sha512:" + hex + hex, "sha256:" + hex[:63], hex},
		},
		{
			"repository", protocol.ValidRepository,
			[]string{"holon/upload/echo", "a.b_c__d-e", strings.Repeat("a", 255)},
			[]string{"", "Holon/echo", "holon//echo", "echo:tag", "echo@sha256:" + hex, strings.Repeat("a", 256)},
		},
		{
			"repository prefix", protocol.ValidImageRepositoryPrefix,
			[]string{"", "ghcr.io/holon", "localhost:5000/holon", "Registry/holon", "docker.io/holon", "[::1]:5000/a/b"},
			[]string{"holon/images", "ghcr.io", "docker.io", "index.docker.io/holon", "ghcr.io/holon:tag", "ghcr.io/Holon"},
		},
		{
			"digest image", protocol.IsValidDigestImage,
			[]string{"ghcr.io/holon/echo@sha256:" + hex, "localhost:5000/echo:v1@sha256:" + hex, "docker.io/library/echo@sha256:" + hex},
			[]string{"ghcr.io/holon/echo", "ghcr.io/holon/echo:v1", "holon/echo@sha256:" + hex, "docker.io/echo@sha256:" + hex, "ghcr.io/echo@sha512:" + hex + hex, "ghcr.io/echo@sha256:" + strings.ToUpper(hex)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, value := range tc.accept {
				if !tc.valid(value) {
					t.Errorf("rejected %q", value)
				}
			}
			for _, value := range tc.reject {
				if tc.valid(value) {
					t.Errorf("accepted %q", value)
				}
			}
		})
	}
}
