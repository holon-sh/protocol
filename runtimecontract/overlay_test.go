package runtimecontract_test

import (
	"testing"

	"github.com/holon-sh/protocol/runtimecontract"
)

func TestOverlayRecordLocation(t *testing.T) {
	valid := runtimecontract.OverlayRecord{Registry: "https://registry.example", Repository: "upload/app", Token: "t"}
	if got, want := valid.Location().String(), "https://registry.example/v2/upload/app"; got != want {
		t.Fatalf("Location() = %s, want %s", got, want)
	}
	for name, change := range map[string]func(*runtimecontract.OverlayRecord){
		"registry without host": func(r *runtimecontract.OverlayRecord) { r.Registry = "https://" },
		"registry scheme":       func(r *runtimecontract.OverlayRecord) { r.Registry = "ftp://registry.example" },
		"repository":            func(r *runtimecontract.OverlayRecord) { r.Repository = "" },
		"token":                 func(r *runtimecontract.OverlayRecord) { r.Token = "" },
	} {
		record := valid
		change(&record)
		if record.Location() != nil {
			t.Errorf("%s: Location() = %s, want nil", name, record.Location())
		}
	}
}
