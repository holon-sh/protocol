package protocol

import (
	"regexp"

	"github.com/holon-sh/protocol/internal/model"
)

const dnsLabelPattern = model.DNSLabelPattern

var (
	dnsLabel = regexp.MustCompile(`^` + dnsLabelPattern + `$`)
	dnsName  = regexp.MustCompile(`^` + dnsLabelPattern + `(\.` + dnsLabelPattern + `)*$`)
)

func ValidPort(port int) bool {
	return port >= model.MinPort && port <= model.MaxPort
}

// ValidDNSLabel uses Kubernetes' lowercase [RFC 1123 §2.1] hostname-label profile.
//
// [RFC 1123 §2.1]: https://www.rfc-editor.org/rfc/rfc1123.html#section-2.1
func ValidDNSLabel(value string) bool {
	return len(value) <= model.MaxDNSLabelBytes && dnsLabel.MatchString(value)
}

func ValidDNSName(value string) bool {
	return len(value) <= 253 && dnsName.MatchString(value)
}
