package archive_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/infrastructure/archive"
)

type entry struct {
	name    string
	body    string
	mode    os.FileMode
	dirOnly bool
}

// buildZip writes an archive with exactly the entries given, including ones a
// well-behaved packer would never produce.
func buildZip(t *testing.T, entries []entry) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "src.zip")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	w := zip.NewWriter(f)
	for _, e := range entries {
		header := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			header.SetMode(e.mode)
		}
		if e.dirOnly {
			header.Name = strings.TrimSuffix(e.name, "/") + "/"
			header.SetMode(os.ModeDir | 0o755)
		}
		writer, createErr := w.CreateHeader(header)
		require.NoError(t, createErr)
		if !e.dirOnly {
			_, writeErr := writer.Write([]byte(e.body))
			require.NoError(t, writeErr)
		}
	}
	require.NoError(t, w.Close())
	return path
}

func extract(t *testing.T, path string, limits archive.Limits) (archive.Result, error) {
	t.Helper()
	res, cleanup, err := archive.ExtractZip(path, t.TempDir(), limits)
	t.Cleanup(cleanup)
	return res, err
}

func TestExtractZip_WritesTheTree(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{
		{name: "main.go", body: "package main"},
		{name: "internal/app/handler.go", body: "package app"},
	})

	res, err := extract(t, path, archive.Limits{})

	require.NoError(t, err)
	assert.Equal(t, 2, res.Files)
	assert.Empty(t, res.StrippedPrefix)

	body, err := os.ReadFile(filepath.Join(res.Dir, "internal/app/handler.go"))
	require.NoError(t, err)
	assert.Equal(t, "package app", string(body))
}

// A GitHub "Download ZIP" wraps everything in one directory; `git archive` does
// not. Both have to land as the repository root, or every finding's path is
// wrong and the client's Code Scanning annotations point nowhere.
func TestExtractZip_StripsASingleTopLevelDirectory(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{
		{name: "repo-9f2a1c/", dirOnly: true},
		{name: "repo-9f2a1c/main.go", body: "package main"},
		{name: "repo-9f2a1c/internal/app.go", body: "package app"},
	})

	res, err := extract(t, path, archive.Limits{})

	require.NoError(t, err)
	assert.Equal(t, "repo-9f2a1c", res.StrippedPrefix)
	assert.FileExists(t, filepath.Join(res.Dir, "main.go"))
	assert.FileExists(t, filepath.Join(res.Dir, "internal/app.go"))
	assert.NoDirExists(t, filepath.Join(res.Dir, "repo-9f2a1c"))
}

func TestExtractZip_KeepsTwoTopLevelDirectories(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{
		{name: "backend/main.go", body: "package main"},
		{name: "frontend/index.js", body: "export {}"},
	})

	res, err := extract(t, path, archive.Limits{})

	require.NoError(t, err)
	assert.Empty(t, res.StrippedPrefix)
	assert.FileExists(t, filepath.Join(res.Dir, "backend/main.go"))
	assert.FileExists(t, filepath.Join(res.Dir, "frontend/index.js"))
}

// Zip-slip. The archive is refused outright rather than having the path
// sanitised, because a rewritten "../../etc/passwd" would be scanned as if it
// were the client's own source.
func TestExtractZip_RefusesPathTraversal(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"../escaped.txt",
		"nested/../../escaped.txt",
		`..\escaped.txt`,
		`nested\..\..\escaped.txt`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := buildZip(t, []entry{
				{name: "main.go", body: "package main"},
				{name: name, body: "owned"},
			})

			parent := t.TempDir()
			_, cleanup, err := archive.ExtractZip(path, parent, archive.Limits{})
			t.Cleanup(cleanup)

			require.ErrorIs(t, err, archive.ErrUnsafePath)
			assert.NoFileExists(t, filepath.Join(parent, "escaped.txt"))
			assert.NoFileExists(t, filepath.Join(filepath.Dir(parent), "escaped.txt"))
		})
	}
}

func TestExtractZip_RefusesAbsolutePaths(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "/etc/cron.d/backdoor", body: "* * * * * root sh"}})

	_, err := extract(t, path, archive.Limits{})

	require.ErrorIs(t, err, archive.ErrUnsafePath)
}

// A symlink is the other half of a zip-slip: the archive creates a link to /etc
// and a later entry writes "through" it. Dropping them is reported, because a
// dropped entry is source the scanners did not see.
func TestExtractZip_DropsSymlinksAndCountsThem(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{
		{name: "main.go", body: "package main"},
		{name: "passwd-link", body: "/etc/passwd", mode: os.ModeSymlink | 0o777},
	})

	res, err := extract(t, path, archive.Limits{})

	require.NoError(t, err)
	assert.Equal(t, 1, res.Files)
	assert.Equal(t, 1, res.SkippedLinks)

	info, lerr := os.Lstat(filepath.Join(res.Dir, "passwd-link"))
	require.Error(t, lerr, "the symlink must not exist: %v", info)
}

func TestExtractZip_RefusesTooManyEntries(t *testing.T) {
	t.Parallel()

	entries := make([]entry, 0, 20)
	for i := range 20 {
		entries = append(entries, entry{name: string(rune('a'+i)) + ".txt", body: "x"})
	}
	path := buildZip(t, entries)

	_, err := extract(t, path, archive.Limits{MaxEntries: 10})

	require.ErrorIs(t, err, archive.ErrTooManyEntries)
}

func TestExtractZip_RefusesDeclaredSizeOverTheLimit(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "big.txt", body: strings.Repeat("A", 4096)}})

	_, err := extract(t, path, archive.Limits{MaxBytes: 1024})

	require.ErrorIs(t, err, archive.ErrTooLarge)
}

// The declared size is attacker-controlled: a bomb understates it so the cheap
// pre-check waves it through. CreateRaw lets the test lie the same way.
//
// archive/zip refuses to hand over more bytes than the header declared, so the
// bomb dies there rather than against the copy budget — which is why the
// budget is defence in depth and this asserts the corruption path instead.
func TestExtractZip_RefusesABombThatUnderstatesItsSize(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("A"), 1<<20) // 1 MiB, compresses to almost nothing

	var deflated bytes.Buffer
	fw, err := flate.NewWriter(&deflated, flate.BestCompression)
	require.NoError(t, err)
	_, err = fw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, fw.Close())

	path := filepath.Join(t.TempDir(), "bomb.zip")
	f, err := os.Create(path)
	require.NoError(t, err)

	w := zip.NewWriter(f)
	raw, err := w.CreateRaw(&zip.FileHeader{
		Name:               "bomb.txt",
		Method:             zip.Deflate,
		CRC32:              crc32.ChecksumIEEE(payload),
		CompressedSize64:   uint64(deflated.Len()),
		UncompressedSize64: 16, // the lie
	})
	require.NoError(t, err)
	_, err = raw.Write(deflated.Bytes())
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	_, err = extract(t, path, archive.Limits{MaxBytes: 4096})

	require.ErrorIs(t, err, archive.ErrCorruptArchive)
}

// Packaging the wrong directory must not read as a repository with no problems.
func TestExtractZip_RefusesAnArchiveWithNoFiles(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "empty-dir/", dirOnly: true}})

	_, err := extract(t, path, archive.Limits{})

	require.ErrorIs(t, err, archive.ErrEmptyArchive)
}

func TestExtractZip_CleanupRemovesTheTree(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "main.go", body: "package main"}})

	res, cleanup, err := archive.ExtractZip(path, t.TempDir(), archive.Limits{})
	require.NoError(t, err)
	require.DirExists(t, res.Dir)

	cleanup()

	assert.NoDirExists(t, res.Dir)
	assert.NotPanics(t, cleanup, "cleanup must be safe to call twice")
}

func TestExtractZip_ReportsAMissingArchive(t *testing.T) {
	t.Parallel()

	_, _, err := archive.ExtractZip(filepath.Join(t.TempDir(), "nope.zip"), t.TempDir(), archive.Limits{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "open archive")
}
