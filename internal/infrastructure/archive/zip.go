// Package archive expands a source archive uploaded by a client into a
// directory the scanners can read.
//
// Everything here treats the archive as hostile input. It arrives over the
// network from a caller whose only credential is an API key, and it is expanded
// on a host that also holds other clients' analyses. So this is the security
// boundary of the upload path, not a convenience wrapper over archive/zip:
// a path that escapes the destination, a declared size that turns out to be a
// lie, or a symlink pointing at /etc are all expected inputs, not surprises.
package archive

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Extraction failures a caller may want to distinguish. Everything else is a
// wrapped I/O error.
var (
	// ErrEmptyArchive means the archive held no regular file. A pipeline that
	// packaged the wrong directory must hear about it, not get a clean report
	// for having scanned nothing.
	ErrEmptyArchive = errors.New("archive contains no files")
	// ErrTooManyEntries caps the entry count: an archive of a million empty
	// files exhausts inodes without ever tripping a size limit.
	ErrTooManyEntries = errors.New("archive has too many entries")
	// ErrTooLarge caps the expanded size, which is the guard against a zip
	// bomb. The declared size is checked first and the real one during the
	// copy, because the declared one is attacker-controlled.
	ErrTooLarge = errors.New("archive expands beyond the size limit")
	// ErrUnsafePath means an entry tried to write outside the destination
	// (zip-slip). It is never sanitised into something harmless: rewriting
	// "../../etc/passwd" to "etc/passwd" would scan an attack as if it were
	// the client's source.
	ErrUnsafePath = errors.New("archive entry escapes the destination")
	// ErrCorruptArchive means an entry did not match its own header: a bad
	// checksum, a truncated stream, or more data than the header declared.
	// The last of those is what a zip bomb looks like once the declared sizes
	// have been budgeted — archive/zip refuses to read past the declared size,
	// so the bomb surfaces here rather than as a disk that filled up.
	ErrCorruptArchive = errors.New("archive entry does not match its header")
)

// Limits bound what one archive may expand into. Zero fields take the default.
type Limits struct {
	// MaxEntries is the number of files and directories the archive may hold.
	MaxEntries int
	// MaxBytes is the total uncompressed size of everything extracted.
	MaxBytes int64
}

// DefaultLimits are sized for a source tree, not for a disk image: a repository
// that expands past two gigabytes is packaging build output by mistake.
func DefaultLimits() Limits {
	return Limits{MaxEntries: 200_000, MaxBytes: 2 << 30}
}

func (l Limits) withDefaults() Limits {
	def := DefaultLimits()
	if l.MaxEntries <= 0 {
		l.MaxEntries = def.MaxEntries
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = def.MaxBytes
	}
	return l
}

// Result reports what came out, so the analysis can say what it actually
// scanned instead of implying it saw everything in the archive.
type Result struct {
	// Dir is the extracted tree.
	Dir string
	// Files and Bytes are what was written.
	Files int
	Bytes int64
	// SkippedLinks counts symlinks and other irregular entries, which are
	// dropped rather than recreated. Reported because a dropped symlink is
	// source the scanners did not see.
	SkippedLinks int
	// StrippedPrefix is the single top-level directory removed from every
	// path, if the archive had one. `git archive` emits none; a GitHub
	// "Download ZIP" wraps everything in `repo-sha/`.
	StrippedPrefix string
}

// ExtractZip expands src into a new directory under parent and returns what it
// wrote, plus a cleanup that removes the tree. The cleanup is always safe to
// call, including after an error.
func ExtractZip(src, parent string, limits Limits) (Result, func(), error) {
	noop := func() {}
	limits = limits.withDefaults()

	reader, err := zip.OpenReader(src)
	if err != nil {
		return Result{}, noop, fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = reader.Close() }()

	if err := precheck(reader.File, limits); err != nil {
		return Result{}, noop, err
	}

	dir, err := os.MkdirTemp(parent, "cortex-src-*")
	if err != nil {
		return Result{}, noop, fmt.Errorf("create extraction dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	res, err := extractAll(reader.File, dir, commonPrefix(reader.File), limits)
	if err != nil {
		cleanup()
		return Result{}, noop, err
	}
	if res.Files == 0 {
		cleanup()
		return Result{}, noop, ErrEmptyArchive
	}

	res.Dir = dir
	return res, cleanup, nil
}

// precheck rejects an archive on what the central directory already says, so a
// bomb is refused before a single byte is written.
func precheck(files []*zip.File, limits Limits) error {
	if len(files) > limits.MaxEntries {
		return fmt.Errorf("%w: %d entries, limit is %d",
			ErrTooManyEntries, len(files), limits.MaxEntries)
	}

	// Declared sizes are attacker-controlled and only ever checked as an early
	// rejection; the real budget is enforced during the copy.
	//
	// The arithmetic stays in uint64, the type the header uses, and each entry
	// is tested against the remaining budget before being added to it. Summing
	// first would let a handful of entries near the top of the range wrap the
	// total back down to something that passes.
	budget := uint64(limits.MaxBytes) // #nosec G115 -- withDefaults leaves MaxBytes > 0
	var declared uint64
	for _, f := range files {
		if f.UncompressedSize64 > budget || declared > budget-f.UncompressedSize64 {
			return fmt.Errorf("%w: declares more than the %d byte limit",
				ErrTooLarge, limits.MaxBytes)
		}
		declared += f.UncompressedSize64
	}
	return nil
}

func extractAll(files []*zip.File, dest, prefix string, limits Limits) (Result, error) {
	res := Result{StrippedPrefix: prefix}
	budget := limits.MaxBytes

	for _, f := range files {
		rel, err := safeName(f.Name, prefix)
		if err != nil {
			return Result{}, err
		}
		if rel == "" {
			continue // the prefix directory itself, or "./"
		}

		target, err := resolve(dest, rel)
		if err != nil {
			return Result{}, err
		}

		info := f.FileInfo()
		switch {
		case info.IsDir():
			if mkErr := os.MkdirAll(target, 0o700); mkErr != nil {
				return Result{}, fmt.Errorf("create %s: %w", rel, mkErr)
			}
		case !info.Mode().IsRegular():
			// Symlinks, devices and named pipes are dropped: recreating a
			// symlink from an untrusted archive is the second half of a
			// zip-slip, and a scanner has no use for a device node.
			res.SkippedLinks++
		default:
			written, wErr := writeFile(f, target, &budget)
			if wErr != nil {
				return Result{}, wErr
			}
			res.Files++
			res.Bytes += written
		}
	}
	return res, nil
}

// safeName validates one archive path and strips the shared prefix. It rejects
// rather than sanitises: see ErrUnsafePath.
func safeName(name, prefix string) (string, error) {
	// Some packers emit backslashes. Normalising first means the ".." check
	// below cannot be bypassed with "..\\..".
	normalised := strings.ReplaceAll(name, `\`, "/")

	if strings.HasPrefix(normalised, "/") || filepath.VolumeName(normalised) != "" {
		return "", fmt.Errorf("%w: %q is absolute", ErrUnsafePath, name)
	}
	for _, segment := range strings.Split(normalised, "/") {
		if segment == ".." {
			return "", fmt.Errorf("%w: %q traverses upwards", ErrUnsafePath, name)
		}
	}

	clean := path.Clean(normalised)
	if clean == "." || clean == "/" {
		return "", nil
	}
	clean = strings.TrimPrefix(clean, "./")

	if prefix != "" {
		if clean == prefix {
			return "", nil
		}
		clean = strings.TrimPrefix(clean, prefix+"/")
	}
	return clean, nil
}

// resolve joins a validated relative path onto dest and confirms the result is
// still inside it. safeName already rejected traversal; this is the check that
// holds even if it did not.
func resolve(dest, rel string) (string, error) {
	target := filepath.Join(dest, filepath.FromSlash(rel))

	cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanDest) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, rel)
	}
	return target, nil
}

// writeFile copies one entry, charging it against the remaining budget. The
// reader is capped at budget+1 so an overrun is detected on the byte after the
// limit rather than after the whole bomb has been written to disk.
func writeFile(f *zip.File, target string, budget *int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return 0, fmt.Errorf("create parent of %s: %w", f.Name, err)
	}

	src, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("open entry %s: %w", f.Name, classify(err))
	}
	defer func() { _ = src.Close() }()

	// 0o600: the scanners run as this process and nothing else needs to read
	// another client's source.
	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", f.Name, err)
	}
	defer func() { _ = dst.Close() }()

	written, err := io.Copy(dst, io.LimitReader(src, *budget+1))
	if err != nil {
		return 0, fmt.Errorf("extract %s: %w", f.Name, classify(err))
	}
	if written > *budget {
		return 0, fmt.Errorf("%w: exceeded while extracting %s", ErrTooLarge, f.Name)
	}
	*budget -= written

	if err := dst.Close(); err != nil {
		return 0, fmt.Errorf("close %s: %w", f.Name, err)
	}
	return written, nil
}

// classify turns archive/zip's two opaque sentinels into one the caller can
// act on. "zip: not a valid zip file" tells an operator nothing about which
// half of the contract the archive broke.
func classify(err error) error {
	if errors.Is(err, zip.ErrFormat) || errors.Is(err, zip.ErrChecksum) {
		return fmt.Errorf("%w: %w", ErrCorruptArchive, err)
	}
	return err
}

// commonPrefix returns the single top-level directory every entry sits under,
// or "" when the archive has none. Stripping it is what makes the endpoint
// accept both `git archive` output and a GitHub "Download ZIP" unchanged.
func commonPrefix(files []*zip.File) string {
	prefix := ""
	for _, f := range files {
		name := strings.TrimPrefix(strings.ReplaceAll(f.Name, `\`, "/"), "./")
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return "" // let safeName deal with it; never strip based on a bad name
		}

		head, _, hasSlash := strings.Cut(name, "/")
		if !hasSlash {
			// A file at the root means there is no wrapping directory. A bare
			// directory entry ("repo-sha/") still cuts, so this is only ever a
			// real file.
			return ""
		}
		if prefix == "" {
			prefix = head
			continue
		}
		if head != prefix {
			return ""
		}
	}
	return prefix
}
