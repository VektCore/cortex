package archive_test

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
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

	res, err := extract(t, path, archive.DefaultLimits())

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

	res, err := extract(t, path, archive.DefaultLimits())

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

	res, err := extract(t, path, archive.DefaultLimits())

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
			_, cleanup, err := archive.ExtractZip(path, parent, archive.DefaultLimits())
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

	_, err := extract(t, path, archive.DefaultLimits())

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

	res, err := extract(t, path, archive.DefaultLimits())

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

	limits := archive.DefaultLimits()
	limits.MaxEntries = 10

	_, err := extract(t, path, limits)

	require.ErrorIs(t, err, archive.ErrTooManyEntries)
}

func TestExtractZip_RefusesDeclaredSizeOverTheLimit(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "big.txt", body: strings.Repeat("A", 4096)}})

	limits := archive.DefaultLimits()
	limits.MaxBytes = 1024

	_, err := extract(t, path, limits)

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

	limits := archive.DefaultLimits()
	limits.MaxBytes = 4096

	_, err = extract(t, path, limits)

	require.ErrorIs(t, err, archive.ErrCorruptArchive)
}

// Packaging the wrong directory must not read as a repository with no problems.
func TestExtractZip_RefusesAnArchiveWithNoFiles(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "empty-dir/", dirOnly: true}})

	_, err := extract(t, path, archive.DefaultLimits())

	require.ErrorIs(t, err, archive.ErrEmptyArchive)
}

func TestExtractZip_CleanupRemovesTheTree(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "main.go", body: "package main"}})

	res, cleanup, err := archive.ExtractZip(path, t.TempDir(), archive.DefaultLimits())
	require.NoError(t, err)
	require.DirExists(t, res.Dir)

	cleanup()

	assert.NoDirExists(t, res.Dir)
	assert.NotPanics(t, cleanup, "cleanup must be safe to call twice")
}

func TestExtractZip_ReportsAMissingArchive(t *testing.T) {
	t.Parallel()

	_, _, err := archive.ExtractZip(filepath.Join(t.TempDir(), "nope.zip"), t.TempDir(), archive.DefaultLimits())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "open archive")
}

// A zero on a security ceiling used to be read as "take the default", so a
// limit an operator meant to tighten could come back wider than the one they
// thought they had set. Every field is required now, and a caller with no
// opinion says so with DefaultLimits().
func TestExtractZip_RefusesNonPositiveLimits(t *testing.T) {
	t.Parallel()

	path := buildZip(t, []entry{{name: "main.go", body: "package main"}})

	for name, limits := range map[string]archive.Limits{
		"nothing set":        {},
		"no entry cap":       {MaxBytes: 1 << 20},
		"no byte cap":        {MaxEntries: 10},
		"negative entry cap": {MaxEntries: -1, MaxBytes: 1 << 20},
		"negative byte cap":  {MaxEntries: 10, MaxBytes: -1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := extract(t, path, limits)

			require.ErrorIs(t, err, archive.ErrInvalidLimits)
		})
	}
}

// The cap is counted against the raw central directory now rather than against
// the parsed entries, and an off-by-one in that count would start refusing
// archives that sit exactly on the limit clients are told they may send.
func TestExtractZip_AcceptsExactlyTheEntryLimit(t *testing.T) {
	t.Parallel()

	entries := make([]entry, 0, 20)
	for i := range 20 {
		entries = append(entries, entry{name: string(rune('a'+i)) + ".txt", body: "x"})
	}
	path := buildZip(t, entries)

	limits := archive.DefaultLimits()
	limits.MaxEntries = 20

	res, err := extract(t, path, limits)

	require.NoError(t, err)
	assert.Equal(t, 20, res.Files)
}

// The central-directory bomb: a file that is nothing but central-directory
// records, which archive/zip turns into one *zip.File each as it parses. An
// entry cap checked after the archive is open is checked too late — the review
// that found this measured 2,000,000 entries and 414.9 MiB of live heap out of
// an 89.6 MiB upload, all of it allocated before MaxEntries was consulted.
//
// So this asserts the allocation, not just the error: reordering the cap back
// below the open would still return ErrTooManyEntries, and would still be the
// bug. Both shapes are covered because neither check alone is enough — the
// declared count is truncated to 16 bits by every non-zip64 packer, and
// archive/zip glosses over that by parsing every record and only then
// comparing the count modulo 65536.
//
// Both archives here are valid: the pre-fix code opened them, parsed all
// 200,000 entries and returned this same error. The only difference the fix
// makes is the 37.7 MiB it no longer allocates to do it.
func TestExtractZip_RefusesACentralDirectoryBombBeforeParsingIt(t *testing.T) {
	const (
		records    = 200_000
		maxEntries = 5_000
		maxAlloc   = 2 << 20 // parsing first costs 37.7 MiB of live heap here
	)

	for _, tc := range []struct {
		name  string
		zip64 bool
	}{
		// 200,000 records declared as 200000 mod 65536 = 3392, which is what a
		// real non-zip64 archive of this size looks like and what archive/zip
		// accepts. Under the cap, so only counting the records catches it.
		{name: "count truncated to the 16-bit field", zip64: false},
		// A zip64 end record can state the count in full, and then the cheap
		// check is enough.
		{name: "count declared honestly in a zip64 record", zip64: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := buildCentralDirectoryBomb(t, records, tc.zip64)
			parent := t.TempDir()

			limits := archive.DefaultLimits()
			limits.MaxEntries = maxEntries

			var err error
			allocated := measureAlloc(func() {
				var cleanup func()
				_, cleanup, err = archive.ExtractZip(path, parent, limits)
				cleanup()
			})

			t.Logf("refused after allocating %d bytes", allocated)

			require.ErrorIs(t, err, archive.ErrTooManyEntries)
			assert.Less(t, allocated, uint64(maxAlloc),
				"refusing the bomb allocated %d bytes: the entry cap is being enforced "+
					"after archive/zip has already parsed the central directory", allocated)
		})
	}
}

// measureAlloc reports the bytes allocated while f ran. TotalAlloc rather than
// a live-heap reading, because the allocation this guards against is transient
// by nature: it is freed as soon as the open fails, and it is still what fills
// the host's memory while it lasts. The caller must not be parallel — the
// counter is process-wide.
func measureAlloc(f func()) uint64 {
	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}

// buildCentralDirectoryBomb writes an archive made only of central-directory
// records: no local headers and no file data, because archive/zip reads none
// of that when it opens an archive. 47 bytes on the wire per entry, which is
// the shape the review's 89.6 MiB / 2,000,000-entry bomb had.
//
// With zip64 the record count is stated honestly in a zip64 end record, which
// is the only way to declare more than 65535 entries. Without it the 16-bit
// field carries a deliberate lie (one entry), which is the case archive/zip
// glosses over by parsing every record and only then comparing the count
// modulo 65536.
func buildCentralDirectoryBomb(t *testing.T, records int, zip64 bool) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bomb.zip")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	out := bufio.NewWriterSize(f, 1<<20)

	const nameLen = 1
	record := make([]byte, 46+nameLen)
	binary.LittleEndian.PutUint32(record[0:4], 0x02014b50)
	binary.LittleEndian.PutUint16(record[28:30], nameLen)
	copy(record[46:], "f")

	for range records {
		_, werr := out.Write(record)
		require.NoError(t, werr)
	}
	dirSize := uint32(len(record) * records)

	if zip64 {
		writeZip64End(t, out, records, dirSize)
	}
	_, err = out.Write(buildEOCD(records, dirSize, zip64))
	require.NoError(t, err)
	require.NoError(t, out.Flush())

	return path
}

func buildEOCD(records int, dirSize uint32, zip64 bool) []byte {
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50)

	if zip64 {
		// The sentinels that send archive/zip to the zip64 record for the real
		// numbers.
		binary.LittleEndian.PutUint16(eocd[8:10], 0xffff)
		binary.LittleEndian.PutUint16(eocd[10:12], 0xffff)
		binary.LittleEndian.PutUint32(eocd[12:16], 0xffffffff)
		binary.LittleEndian.PutUint32(eocd[16:20], 0xffffffff)
		return eocd
	}

	// Truncated to the field's 16 bits, as every non-zip64 packer does.
	// archive/zip only ever compares the count modulo 65536, so this opens
	// cleanly and the declared number is far below the real one.
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(records))
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(records))
	binary.LittleEndian.PutUint32(eocd[12:16], dirSize)
	binary.LittleEndian.PutUint32(eocd[16:20], 0)
	return eocd
}

func writeZip64End(t *testing.T, out *bufio.Writer, records int, dirSize uint32) {
	t.Helper()

	end := make([]byte, 56)
	binary.LittleEndian.PutUint32(end[0:4], 0x06064b50)
	binary.LittleEndian.PutUint64(end[4:12], 44) // size of the rest of this record
	binary.LittleEndian.PutUint64(end[24:32], uint64(records))
	binary.LittleEndian.PutUint64(end[32:40], uint64(records))
	binary.LittleEndian.PutUint64(end[40:48], uint64(dirSize))
	binary.LittleEndian.PutUint64(end[48:56], 0)
	_, err := out.Write(end)
	require.NoError(t, err)

	locator := make([]byte, 20)
	binary.LittleEndian.PutUint32(locator[0:4], 0x07064b50)
	binary.LittleEndian.PutUint64(locator[8:16], uint64(dirSize)) // the record above
	binary.LittleEndian.PutUint32(locator[16:20], 1)
	_, err = out.Write(locator)
	require.NoError(t, err)
}

// The End Of Central Directory record is found by scanning backwards for its
// signature, because an archive comment of up to 64 KiB may sit after it.
// Reading it from a fixed offset would make the entry bound miss the directory
// and wave the archive through without counting anything.
func TestExtractZip_HandlesAnArchiveComment(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "commented.zip")
	f, err := os.Create(path)
	require.NoError(t, err)

	w := zip.NewWriter(f)
	// Long enough that the record is outside the first window searched.
	require.NoError(t, w.SetComment(strings.Repeat("c", 40_000)))
	for _, name := range []string{"main.go", "app.go"} {
		writer, createErr := w.Create(name)
		require.NoError(t, createErr)
		_, writeErr := writer.Write([]byte("package main"))
		require.NoError(t, writeErr)
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	overTheCap := archive.DefaultLimits()
	overTheCap.MaxEntries = 1
	_, err = extract(t, path, overTheCap)
	require.ErrorIs(t, err, archive.ErrTooManyEntries, "the directory was not found behind the comment")

	res, err := extract(t, path, archive.DefaultLimits())
	require.NoError(t, err)
	assert.Equal(t, 2, res.Files)
}

// A self-extracting archive carries a stub before the zip data, which shifts
// every offset the directory declares. archive/zip compensates; the entry
// bound has to agree with it about where the directory begins, or it counts
// the wrong region — refusing a legitimate archive, or counting nothing in one
// that packs its records somewhere else.
func TestExtractZip_HandlesDataPrependedToTheArchive(t *testing.T) {
	t.Parallel()

	inner := buildZip(t, []entry{
		{name: "main.go", body: "package main"},
		{name: "app.go", body: "package app"},
	})
	body, err := os.ReadFile(inner)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "sfx.zip")
	stub := bytes.Repeat([]byte("S"), 4096)
	require.NoError(t, os.WriteFile(path, append(stub, body...), 0o600))

	overTheCap := archive.DefaultLimits()
	overTheCap.MaxEntries = 1
	_, err = extract(t, path, overTheCap)
	require.ErrorIs(t, err, archive.ErrTooManyEntries, "the shifted directory was not counted")

	res, err := extract(t, path, archive.DefaultLimits())
	require.NoError(t, err)
	assert.Equal(t, 2, res.Files)
}
