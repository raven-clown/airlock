// Package naming builds and splits the prefixed tool names airlock exposes.
package naming

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Separator joins a server name and a tool name.
const Separator = "__"

const maxToolName = 128

var serverName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidServerName reports whether s matches ^[a-z0-9][a-z0-9-]{0,31}$.
func ValidServerName(s string) bool {
	return serverName.MatchString(s)
}

// Join returns server + "__" + tool, or an error saying why the result is not a valid MCP tool name.
func Join(server, tool string) (string, error) {
	if !ValidServerName(server) {
		return "", fmt.Errorf("invalid server name %q", server)
	}
	if tool == "" {
		return "", errors.New("tool name is empty")
	}
	name := server + Separator + tool
	if len(name) > maxToolName {
		return "", fmt.Errorf("tool name %q is longer than %d characters", name, maxToolName)
	}
	for i := 0; i < len(tool); i++ {
		if !validToolByte(tool[i]) {
			return "", fmt.Errorf("tool name %q has characters other than letters, digits, underscore, dash and dot", tool)
		}
	}
	return name, nil
}

// Split splits name at the first "__". ok is false when there is no separator.
func Split(name string) (server, tool string, ok bool) {
	server, tool, ok = strings.Cut(name, Separator)
	if !ok {
		return "", "", false
	}
	return server, tool, true
}

func validToolByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}
