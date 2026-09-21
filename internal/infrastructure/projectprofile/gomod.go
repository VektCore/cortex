package projectprofile

import (
	"bufio"
	"bytes"
	"os"
	"strings"
)

// go.mod contributes the module path and nothing else, because Go has no
// concept of a declared-but-not-compiled directory.
//
// It is worth reading anyway for the note it lets this package make: the
// obvious "exclude vendor/" heuristic is wrong for Go. A vendored Go tree is
// compiled into the binary and ships with it, so a vulnerability there is a
// vulnerability in the product. That is the clearest example of why nothing
// here excludes on the name of a directory.

// readGoMod returns the module path declared at rel, and whether go.mod exists.
func readGoMod(root, rel string) (string, bool) {
	raw, err := os.ReadFile(abs(root, rel))
	if err != nil {
		return "", false
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), true
		}
	}
	return "", true
}
