package scim

import (
	"encoding/json"
	"strings"
)

func parseUserName(expression string) (string, bool) {
	fields := strings.SplitN(expression, " ", 3)
	var value string
	if len(fields) != 3 || !strings.EqualFold(fields[0], "userName") || !strings.EqualFold(fields[1], "eq") || !strings.HasPrefix(fields[2], `"`) ||
		json.Unmarshal([]byte(fields[2]), &value) != nil || value == "" {
		return "", false
	}
	return value, true
}
