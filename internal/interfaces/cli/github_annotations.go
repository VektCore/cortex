package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// emitGitHubAnnotations writes GitHub Actions workflow commands to w for each
// finding. Only called when GITHUB_ACTIONS=true.
func emitGitHubAnnotations(w io.Writer, findings []finding.Finding) {
	for _, f := range findings {
		level := ghAnnotationLevel(f.Severity())
		loc := f.Location()
		title := escapeGHAnnotationProperty(f.RuleID().String())
		msg := escapeGHAnnotationData(f.Message().String())
		fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			level, loc.File(), loc.StartLine(), title, msg)
	}
}

// isGitHubActions reports whether the process is running inside GitHub Actions.
func isGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

func ghAnnotationLevel(sev shared.Severity) string {
	switch sev {
	case shared.SeverityCritical, shared.SeverityHigh:
		return "error"
	case shared.SeverityMedium:
		return "warning"
	case shared.SeverityLow, shared.SeverityInfo:
		return "notice"
	default:
		return "notice"
	}
}

// escapeGHAnnotationProperty escapes a value for use in annotation properties
// (file=, line=, title=). Commas and colons must be percent-encoded.
func escapeGHAnnotationProperty(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}

// escapeGHAnnotationData escapes a value for use as annotation message data.
func escapeGHAnnotationData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}
