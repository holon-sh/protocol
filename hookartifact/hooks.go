package hookartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/holon-sh/protocol"
)

// boundaryVersion is a [semantic version] without build metadata.
//
// [semantic version]: https://semver.org/spec/v2.0.0.html
var boundaryVersion = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$`)

var runtimes = map[string]string{".js": "node", ".ts": "node", ".py": "python", "": "executable"}

var versionedEvents = map[string]bool{
	"pre-install": false, "post-install": false, "pre-delete": false, "post-delete": false,
	"pre-upgrade": true, "post-upgrade": true, "pre-downgrade": true, "post-downgrade": true,
}

func VersionedEvent(event string) bool {
	return versionedEvents[event]
}

func Parse(name string, executable bool) (protocol.Hook, error) {
	directory, file := path.Split(name)
	version, inside := strings.CutPrefix(directory, "hooks/")
	ext := path.Ext(file)
	runtime, supported := runtimes[ext]
	if !inside || !supported {
		return protocol.Hook{}, fmt.Errorf("unsupported hook file %s", name)
	}
	if runtime == "executable" && !executable {
		return protocol.Hook{}, fmt.Errorf("%s must be executable", name)
	}
	h := protocol.Hook{Event: strings.TrimSuffix(file, ext), Version: strings.TrimSuffix(version, "/"), Path: name, Runtime: runtime}
	versioned, known := versionedEvents[h.Event]
	if !known || versioned != (h.Version != "") || ValidateDirectory(strings.TrimSuffix(directory, "/")) != nil {
		return protocol.Hook{}, fmt.Errorf("invalid lifecycle event or version boundary: %s", name)
	}
	return h, nil
}

func Discover(root fs.FS) ([]protocol.Hook, error) {
	var found []protocol.Hook
	err := fs.WalkDir(root, "hooks", func(name string, entry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && name == "hooks" {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return ValidateDirectory(name)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("hook must be a regular file or directory: %s", name)
		}
		h, err := Parse(name, info.Mode().Perm()&0o111 != 0)
		if err != nil {
			return err
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		h.Checksum, err = Checksum(file)
		found = append(found, h)
		return errors.Join(err, file.Close())
	})
	if err != nil {
		return nil, err
	}
	return Validate(found)
}

func ValidateDirectory(name string) error {
	if name == "hooks" {
		return nil
	}
	if !boundaryVersion.MatchString(strings.TrimPrefix(name, "hooks/")) {
		return fmt.Errorf("invalid lifecycle boundary directory: %s", name)
	}
	return nil
}

func Checksum(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func Validate(found []protocol.Hook) ([]protocol.Hook, error) {
	slices.SortFunc(found, func(a, b protocol.Hook) int { return strings.Compare(a.Key(), b.Key()) })
	for i, h := range found {
		if i > 0 && found[i-1].Key() == h.Key() {
			return nil, fmt.Errorf("duplicate lifecycle handler: %s", h.Key())
		}
		parsed, err := Parse(h.Path, true)
		parsed.Checksum = h.Checksum
		if err != nil || parsed != h {
			return nil, fmt.Errorf("invalid hook index entry: %s", h.Path)
		}
	}
	return found, nil
}
