package protocol

import (
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

func NormalizeEgressHost(host string) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if address.Zone() != "" || !address.IsGlobalUnicast() && !address.IsLinkLocalUnicast() {
			return "", errors.New("egress requires a unicast destination IP")
		}
		return address.String(), nil
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	domain := strings.TrimSuffix(name, ".")
	if !strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz") || len(domain) > 253 || !strings.Contains(domain, ".") ||
		slices.ContainsFunc(strings.Split(domain, "."), func(label string) bool { return !ValidDNSLabel(label) }) {
		return "", errors.New("egress requires exact DNS hostnames or IP addresses")
	}
	return name, nil
}

func (policy *Egress) UnmarshalJSON(data []byte) error {
	type plainEgress Egress
	var decoded plainEgress
	if err := DecodeJSONNonNull(data, &decoded); err != nil {
		return err
	}
	var err error
	*policy, err = Egress(decoded).Normalize()
	return err
}

func (policy Egress) Normalize() (Egress, error) {
	if policy == nil {
		return nil, nil
	}
	hosts := map[Template][]int32{}
	for _, destination := range policy {
		host := destination.Host
		if len(TemplateInputs(host)) == 0 {
			var err error
			if host, err = NormalizeEgressHost(host); err != nil {
				return nil, err
			}
		}
		if len(destination.Ports) == 0 {
			return nil, errors.New("egress destinations require a nonempty ports list")
		}
		if slices.ContainsFunc(destination.Ports, func(port int32) bool { return !ValidPort(int(port)) }) {
			return nil, errors.New("egress ports must be TCP port numbers from 1 to 65535")
		}
		hosts[host] = append(hosts[host], destination.Ports...)
	}
	normalized := make(Egress, 0, len(hosts))
	for _, host := range slices.Sorted(maps.Keys(hosts)) {
		ports := hosts[host]
		slices.Sort(ports)
		normalized = append(normalized, EgressDestination{Host: host, Ports: slices.Compact(ports)})
	}
	return normalized, nil
}

// Validate checks the hosts against the app's inputs. Hosts land in network policy, so a placeholder may name only a
// declared, non-secret input, and each host must be valid with every placeholder replaced by a DNS name.
func (policy Egress) Validate(env map[string]Input) error {
	declared := func(name string) (string, bool) {
		input, ok := env[name]
		return "holon.invalid", ok && !input.IsSecret
	}
	for _, destination := range policy {
		host, complete := Expand(destination.Host, declared)
		if !complete {
			return errors.New("egress hosts may name only declared, non-secret inputs")
		}
		if _, err := NormalizeEgressHost(host); err != nil {
			return err
		}
	}
	return nil
}
