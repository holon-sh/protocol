package protocol

import "regexp"

const dnsLabelPattern = `[a-z0-9]([-a-z0-9]*[a-z0-9])?`

var (
	dnsLabel = regexp.MustCompile(`^` + dnsLabelPattern + `$`)
	dnsName  = regexp.MustCompile(`^` + dnsLabelPattern + `(\.` + dnsLabelPattern + `)*$`)
)

func ValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// ValidDNSLabel uses Kubernetes' lowercase [RFC 1123 §2.1] hostname-label profile.
//
// [RFC 1123 §2.1]: https://www.rfc-editor.org/rfc/rfc1123.html#section-2.1
func ValidDNSLabel(value string) bool {
	return len(value) <= 63 && dnsLabel.MatchString(value)
}

func ValidDNSName(value string) bool {
	return len(value) <= 253 && dnsName.MatchString(value)
}
