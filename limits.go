package protocol

import (
	"errors"
	"fmt"
	"iter"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"time"
)

// Limits bounds how often an app is called. The server limit counts every MCP request to the app, and a tool's limit
// counts that tool's calls as well: a request is refused when any limit that counts it is spent.
type Limits struct {
	// +optional
	Observe bool `description:"Report the requests these limits would refuse without refusing them." json:"observe,omitempty"`
	// +optional
	Server *Limit `description:"Counts every MCP request to the app." json:"server,omitempty"`
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	Tools map[string]Limit `description:"Counts each call of the named tool, beside the server limit." json:"tools,omitempty" maxProperties:"256"`
}

// Limit holds one rate for each way of telling callers apart. A request counts against every rate that names it.
//
// +mapType=atomic
type Limit struct {
	// +optional
	Total Rate `description:"All callers together. A count per s, min or h, as in 600/min." json:"total,omitempty" pattern:"^[1-9][0-9]{0,8}/(s|min|h)$"`
	// +optional
	Identity Rate `description:"Each signed-in identity. A count per s, min or h, as in 600/min." json:"identity,omitempty" pattern:"^[1-9][0-9]{0,8}/(s|min|h)$"`
	// +optional
	Caller Rate `description:"Each app of the session that calls this one. A count per s, min or h, as in 600/min." json:"caller,omitempty" pattern:"^[1-9][0-9]{0,8}/(s|min|h)$"`
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	Callers map[string]Rate `description:"The named calling app's rate, in place of caller." json:"callers,omitempty" maxProperties:"256"`
}

// Rate is a number of requests per second, minute or hour, as in 600/min. That many may arrive at once.
//
// +kubebuilder:validation:Pattern="^[1-9][0-9]{0,8}/(s|min|h)$"
type Rate string

var (
	ratePattern = regexp.MustCompile(`^([1-9][0-9]{0,8})/(s|min|h)$`)
	rateWindows = map[string]time.Duration{"s": time.Second, "min": time.Minute, "h": time.Hour}
)

// Parse returns the requests the rate admits per window.
func (rate Rate) Parse() (requests int, window time.Duration, err error) {
	parts := ratePattern.FindStringSubmatch(string(rate))
	if parts == nil {
		return 0, 0, errors.New("a rate is a count per s, min or h, as in 600/min")
	}
	requests, _ = strconv.Atoi(parts[1])
	return requests, rateWindows[parts[2]], nil
}

// Rules yields the server limit and then each tool's, under the path that names it in an app's declaration.
func (limits *Limits) Rules() iter.Seq2[string, Limit] {
	return func(yield func(string, Limit) bool) {
		if limits == nil || limits.Server != nil && !yield("limits.server", *limits.Server) {
			return
		}
		for name, limit := range limits.Tools {
			if !yield("limits.tools["+name+"]", limit) {
				return
			}
		}
	}
}

func (limits *Limits) UnmarshalJSON(data []byte) error {
	type plainLimits Limits
	if err := DecodeJSONNonNull(data, (*plainLimits)(limits)); err != nil {
		return err
	}
	return limits.Validate()
}

func (limits *Limits) Validate() error {
	if limits == nil {
		return nil
	}
	if len(limits.Tools) > 256 || slices.ContainsFunc(slices.Collect(maps.Keys(limits.Tools)), func(name string) bool { return !ValidMCPName(name) }) {
		return errors.New("limits.tools must name at most 256 tools")
	}
	for path, limit := range limits.Rules() {
		if len(limit.Callers) > 256 || !ValidAppNames(slices.Collect(maps.Keys(limit.Callers))) {
			return fmt.Errorf("%s.callers must name at most 256 apps", path)
		}
		rates := map[string]Rate{}
		for name, rate := range limit.Callers {
			rates["callers["+name+"]"] = rate
		}
		for name, rate := range map[string]Rate{"total": limit.Total, "identity": limit.Identity, "caller": limit.Caller} {
			if rate != "" {
				rates[name] = rate
			}
		}
		for _, name := range slices.Sorted(maps.Keys(rates)) {
			if _, _, err := rates[name].Parse(); err != nil {
				return fmt.Errorf("%s.%s: %w", path, name, err)
			}
		}
	}
	return nil
}
