package projectprofile_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/vektcore/cortex/internal/infrastructure/projectprofile"
)

func TestAgainstRealRepository(t *testing.T) {
	root := os.Getenv("REAL_REPO")
	if root == "" {
		t.Skip("REAL_REPO not set")
	}
	p := projectprofile.Load(context.Background(), root)
	fmt.Println(p.Explain())
	fmt.Println("ExcludeGlobs:", p.ExcludeGlobs())
	fmt.Println("ComposeWith(defaults):", p.ComposeWith([]string{"node_modules/", "vendor/", ".venv/", "*.min.js"}))
	fmt.Println("Workspaces:", p.Workspaces, "GoModule:", p.GoModule)
}
