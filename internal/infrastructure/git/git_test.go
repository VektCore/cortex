package git_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gitinfra "github.com/vektcore/cortex/internal/infrastructure/git"
)

// gitAvailable returns true when git is in PATH.
func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// initRepo creates a throwaway git repo with one commit and returns its path.
func initRepo(t *testing.T) string {
	t.Helper()
	if !gitAvailable() {
		t.Skip("git not in PATH")
	}
	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Stdout = nil
		cmd.Stderr = nil
		require.NoError(t, cmd.Run())
	}
	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	run("checkout", "-b", "main")
	f := filepath.Join(root, "hello.txt")
	require.NoError(t, os.WriteFile(f, []byte("hello"), 0o644))
	run("add", ".")
	run("commit", "-m", "initial")
	return root
}

func TestRepository_CurrentRevision(t *testing.T) {
	t.Parallel()
	repo := initRepo(t)

	r := gitinfra.New()
	rev, err := r.CurrentRevision(context.Background(), repo).Get()
	require.NoError(t, err)
	assert.NotEmpty(t, rev.Commit())
	assert.Equal(t, "main", rev.Branch())
}

func TestRepository_ChangedFiles_SingleCommit(t *testing.T) {
	t.Parallel()
	repo := initRepo(t)

	r := gitinfra.New()
	// Single-commit repo — ChangedFiles should return empty (not error)
	files, err := r.ChangedFiles(context.Background(), repo, "").Get()
	require.NoError(t, err)
	assert.Nil(t, files)
}

func TestRepository_ChangedFiles_WithTwoCommits(t *testing.T) {
	t.Parallel()
	if !gitAvailable() {
		t.Skip("git not in PATH")
	}
	repo := initRepo(t)
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Run() //nolint:errcheck
	}
	f := filepath.Join(repo, "new.txt")
	require.NoError(t, os.WriteFile(f, []byte("new"), 0o644))
	run("add", ".")
	run("commit", "-m", "second")

	r := gitinfra.New()
	files, err := r.ChangedFiles(context.Background(), repo, "").Get()
	require.NoError(t, err)
	assert.Contains(t, files, "new.txt")
}

func TestRepository_CurrentRevision_NonGitDir(t *testing.T) {
	t.Parallel()
	if !gitAvailable() {
		t.Skip("git not in PATH")
	}
	r := gitinfra.New()
	_, err := r.CurrentRevision(context.Background(), t.TempDir()).Get()
	assert.Error(t, err, "non-git directory must return error")
}
