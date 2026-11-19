package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/holon-sh/protocol"
)

func TestLimitsContract(t *testing.T) {
	var app protocol.App
	declared := `{"name":"board","access":{"server":{}},"limits":{"server":{"total":"6000/min","identity":"10/s"},` +
		`"tools":{"put_image":{"caller":"1/h","callers":{"importer":"500/min"}}}}}`
	if err := json.Unmarshal([]byte(declared), &app); err != nil {
		t.Fatal(err)
	}
	if requests, window, err := app.Limits.Server.Total.Parse(); err != nil || requests != 6000 || window != time.Minute {
		t.Errorf("6000/min parsed as %d per %s: %v", requests, window, err)
	}
	for limits, field := range map[string]string{
		`{"server":{"total":"0/min"}}`:                     "limits.server.total",
		`{"server":{"identity":"10/day"}}`:                 "limits.server.identity",
		`{"tools":{"draw":{"caller":"1e3/s"}}}`:            "limits.tools[draw].caller",
		`{"tools":{"draw":{"callers":{"importer":""}}}}`:   "limits.tools[draw].callers[importer]",
		`{"server":{"callers":{"Not An App":"1/s"}}}`:      "limits.server.callers",
		`{"server":{"address":"1/s"}}`:                     "address",
		`{"tools":{"line\nbreak":{"total":"1/s"}}}`:        "limits.tools",
		`{"server":{"total":"1/s"},"tools":{"draw":null}}`: "null",
		`{"server":{"total":"12345678901/s"}}`:             "limits.server.total",
	} {
		err := json.Unmarshal([]byte(`{"name":"board","access":{"server":{}},"limits":`+limits+`}`), &protocol.App{})
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: got %v, want an error naming %s", limits, err, field)
		}
	}
}
