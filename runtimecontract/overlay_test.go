package runtimecontract_test

import (
	"strings"
	"testing"

	"github.com/holon-sh/protocol/runtimecontract"
)

func TestOverlayRecordBlob(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	valid := runtimecontract.OverlayRecord{
		Registry: "https://registry.example", Repository: "upload/app", Token: "t", Digest: digest,
		MediaType: runtimecontract.OverlayMediaType,
	}
	if got, want := valid.Blob().String(), "https://registry.example/v2/upload/app/blobs/"+digest; got != want {
		t.Fatalf("Blob() = %s, want %s", got, want)
	}
	for name, change := range map[string]func(*runtimecontract.OverlayRecord){
		"registry without host": func(r *runtimecontract.OverlayRecord) { r.Registry = "https://" },
		"registry scheme":       func(r *runtimecontract.OverlayRecord) { r.Registry = "ftp://registry.example" },
		"repository":            func(r *runtimecontract.OverlayRecord) { r.Repository = "" },
		"token":                 func(r *runtimecontract.OverlayRecord) { r.Token = "" },
		"digest":                func(r *runtimecontract.OverlayRecord) { r.Digest = "sha256:abc" },
		"media type":            func(r *runtimecontract.OverlayRecord) { r.MediaType = "application/json" },
	} {
		record := valid
		change(&record)
		if record.Blob() != nil {
			t.Errorf("%s: Blob() = %s, want nil", name, record.Blob())
		}
	}
}
