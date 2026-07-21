package admin

import (
	"regexp"
	"strings"
)

var releaseVersionPattern = regexp.MustCompile(`^(\d+\.\d+\.\d+)(-rc)?$`)

func formatDisplayVersion(version string) string {
	trimmed := strings.TrimSpace(version)
	withoutPrefix := strings.TrimPrefix(strings.ToLower(trimmed), "v")
	match := releaseVersionPattern.FindStringSubmatch(withoutPrefix)
	if match == nil {
		return trimmed
	}
	if match[2] != "" {
		return "v" + match[1] + "-RC"
	}
	return "v" + match[1]
}
