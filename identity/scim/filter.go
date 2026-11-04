package scim

import (
	"encoding/json"
	"strings"
)

func parseFilter(expression string) (Filter, error) {
	if expression == "" {
		return Filter{}, nil
	}
	fields := strings.SplitN(expression, " ", 3)
	var value string
	if len(fields) != 3 || !strings.EqualFold(fields[1], "eq") || !strings.HasPrefix(fields[2], `"`) ||
		json.Unmarshal([]byte(fields[2]), &value) != nil || value == "" {
		return Filter{}, ErrFilter
	}
	switch strings.ToLower(fields[0]) {
	case "username":
		return Filter{UserName: value}, nil
	case "emails.value":
		return Filter{Email: value}, nil
	case "groups.value":
		return Filter{Group: value}, nil
	}
	return Filter{}, ErrFilter
}

func (f Filter) expression() (string, error) {
	var terms []string
	for _, term := range [][2]string{{"userName", f.UserName}, {"emails.value", f.Email}, {"groups.value", f.Group}} {
		if term[1] != "" {
			literal, _ := json.Marshal(term[1])
			terms = append(terms, term[0]+" eq "+string(literal))
		}
	}
	switch len(terms) {
	case 0:
		return "", nil
	case 1:
		return terms[0], nil
	}
	return "", ErrFilter
}
