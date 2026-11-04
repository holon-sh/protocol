package hookartifact

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestDiscoveryContract(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   fstest.MapFS
		invalid bool
	}{
		{
			"languages",
			fstest.MapFS{
				"hooks/pre-install.ts":       {},
				"hooks/post-install.py":      {},
				"hooks/1.2.0/pre-upgrade.js": {},
				"hooks/1.2.0/post-downgrade": {Mode: 0o755},
			},
			false,
		},

		{"duplicate", fstest.MapFS{"hooks/pre-install.js": {}, "hooks/pre-install.py": {}}, true},
		{"empty malformed boundary", fstest.MapFS{"hooks/1.2": {Mode: fs.ModeDir}}, true},
		{"metadata", fstest.MapFS{"hooks/1.2.0+build/pre-upgrade.py": {}}, true},
		{"prerelease", fstest.MapFS{"hooks/1.2.0-rc.1/pre-upgrade.py": {}}, false},
		{"leading zero", fstest.MapFS{"hooks/01.2.0/pre-upgrade.py": {}}, true},
		{"version prefix", fstest.MapFS{"hooks/v1.2.0/pre-upgrade.py": {}}, true},
		{"placement", fstest.MapFS{"hooks/pre-upgrade.py": {}}, true},
		{"rollback", fstest.MapFS{"hooks/1.2.0/pre-rollback.py": {}}, true},
		{"symlink", fstest.MapFS{"hooks/pre-install.py": {Mode: fs.ModeSymlink}}, true},
		{"executable permission", fstest.MapFS{"hooks/pre-install": {}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := Discover(tc.files)
			if (err != nil) != tc.invalid {
				t.Fatalf("hooks=%v error=%v", found, err)
			}
			if !tc.invalid && len(found) != len(tc.files) {
				t.Fatalf("missing hooks: %v", found)
			}
		})
	}
}
