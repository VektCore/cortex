package cli

import (
	"github.com/spf13/cobra"

	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
)

// addRemoteFlags declares the flags every command that accepts a repository
// target needs.
func addRemoteFlags(cmd *cobra.Command) {
	cmd.Flags().String("ref", "",
		"branch, tag or commit to check out when the target is a remote repository")
	cmd.Flags().Bool("full-history", false,
		"clone the full history instead of a shallow clone (needed to scan commit history)")
}

// resolveTarget turns a command argument into a local directory to analyse.
// A remote URL is cloned into a temporary directory; the returned cleanup
// removes it and is always safe to call.
//
//	cortex scan .
//	cortex scan github.com/org/repo --ref main
//	cortex scan git@github.com:org/repo.git
func resolveTarget(cmd *cobra.Command, target string) (string, func(), error) {
	noop := func() {}

	if !gitinfra.IsRemoteURL(target) {
		return target, noop, nil
	}

	ref, _ := cmd.Flags().GetString("ref")
	full, _ := cmd.Flags().GetBool("full-history")

	cmd.Printf("cloning %s%s\n", gitinfra.Redact(gitinfra.NormalizeURL(target)), refSuffix(ref))

	dir, cleanup, err := gitinfra.Clone(cmd.Context(), gitinfra.CloneSpec{
		URL:  target,
		Ref:  ref,
		Full: full,
	})
	if err != nil {
		return "", noop, scannerErr(err.Error())
	}
	return dir, cleanup, nil
}

func refSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return " @ " + ref
}
