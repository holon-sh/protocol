package protocol

import (
	"slices"
	"testing"
)

func TestEveryPlaneHasItsOwnHost(t *testing.T) {
	const origin = "https://example.test"
	for _, test := range []struct {
		host    string
		plane   Plane
		session string
		control bool
	}{
		{"example.test", BasePlane, "", false},
		{"dev.example.test", DevPlane, "", true},
		{"admin.example.test", AdminPlane, "", true},
		{"account.example.test", AccountPlane, "", true},
		{"gentle-otter.example.test", SessionPlane, "gentle-otter", false},
	} {
		plane, session, ok := ParseHost(origin, test.host)
		_, control := ParseControlAudience(origin, "https://"+test.host)
		if !ok || plane != test.plane || session != test.session || control != test.control {
			t.Errorf("%s = %s %q %t, control %t", test.host, plane, session, ok, control)
		}
	}
	for _, name := range []string{"dev", "admin", "account", ProductionName} {
		if ValidSessionName(name) {
			t.Errorf("a session may be named %q, which a plane or production uses", name)
		}
	}
	if scopes := ControlScopes(AccountPlane); !slices.Equal(scopes, nil) {
		t.Errorf("account plane scopes = %v", scopes)
	}
}
