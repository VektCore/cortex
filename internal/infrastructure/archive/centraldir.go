package archive

import (
	"archive/zip"
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// This file enforces the entry cap before archive/zip ever sees the file.
//
// zip.NewReader allocates one *zip.File per central-directory record while it
// parses, so by the time len(reader.File) can be compared with MaxEntries the
// allocation the cap exists to prevent has already happened. Measured: a
// 89.6 MiB file that is nothing but central-directory records parses into
// 2,000,000 entries and 414.9 MiB of live heap — a 4.6x amplification of the
// upload, and at the 256 MiB upload ceiling roughly 1.2 GiB of transient heap
// per extraction, multiplied by the number of workers, on a host that also
// runs six Postgres instances.
//
// Two checks, because either one alone is escapable:
//
//  1. The record count the End Of Central Directory declares. O(1), and it is
//     what an honest archive (or a zip64 one, which can state a count larger
//     than the 16-bit field) says. It is not sufficient: archive/zip does not
//     trust that count either — its parse loop reads headers until one fails
//     and only compares the count modulo 65536 at the end — so an understated
//     count still gets every record parsed before the open errors out.
//  2. A walk of the central directory that counts records for real and gives
//     up the moment it passes the cap. It reads the 46-byte fixed header and
//     skips the variable-length fields, so it allocates nothing per entry and
//     never reads more than MaxEntries+1 records.
//
// Rejected alternative: bounding by file size, on the grounds that a record is
// at least 46 bytes so a file cannot hold more than size/46 of them. That
// bound is useless in the direction we need — at the 256 MiB ceiling it still
// permits 5.8M entries — and tightening it into "size/46 > MaxEntries" would
// reject legitimate archives: a real record averages around 76 bytes with the
// file name, so a node_modules tree with 150k files would be refused under a
// 200k cap.
//
// The offsets and quirks below mirror archive/zip's own readDirectoryEnd. A
// bound that disagrees with the parser it protects about where the central
// directory begins is not a bound at all.

const (
	eocdSignature    = 0x06054b50
	eocdLen          = 22
	eocd64LocSig     = 0x07064b50
	eocd64LocLen     = 20
	eocd64Sig        = 0x06064b50
	eocd64Len        = 56
	centralHeaderSig = 0x02014b50
	centralHeaderLen = 46
)

// centralDir is the part of the End Of Central Directory record this bound
// needs: where the directory lives, and how many records it claims to hold.
type centralDir struct {
	end     int64  // offset of the record itself; the directory ends here
	records uint64 // declared number of central-directory records
	size    uint64 // declared byte length of the central directory
	offset  uint64 // declared start of the central directory
}

// boundEntryCount refuses an archive whose central directory holds more than
// maxEntries records, reading only the directory's fixed headers.
func boundEntryCount(r io.ReaderAt, size int64, maxEntries int) error {
	dir, ok := readCentralDir(r, size)
	if !ok {
		// Nothing we can read a directory out of. Deferring is safe: every
		// case that lands here is one archive/zip rejects in readDirectoryEnd,
		// which is before it parses a single record.
		return nil
	}

	limit := uint64(maxEntries) // #nosec G115 -- Limits.Validate leaves MaxEntries > 0
	if dir.records > limit {
		return fmt.Errorf("%w: central directory declares %d entries, limit is %d",
			ErrTooManyEntries, dir.records, maxEntries)
	}

	for _, start := range dir.starts(size) {
		if countRecords(r, start, dir.end, maxEntries) > maxEntries {
			return fmt.Errorf("%w: central directory holds more than %d entries",
				ErrTooManyEntries, maxEntries)
		}
	}
	return nil
}

// starts returns every offset archive/zip might begin reading the central
// directory from. It normally seeks to end-directorySize, but when that
// implies data prepended to the archive (a self-extracting exe) it prefers the
// declared offset if a record really sits there. Both have to be walked: an
// archive that declares a tiny directory while packing records from byte zero
// would otherwise slip past a bound that only looked at the first.
func (d centralDir) starts(size int64) []int64 {
	if d.size > math.MaxInt64 || d.offset > math.MaxInt64 {
		return nil
	}
	dirSize, dirOffset := int64(d.size), int64(d.offset) // #nosec G115 -- bounded just above

	base := d.end - dirSize - dirOffset
	if o := base + dirOffset; o < 0 || o >= size {
		return nil // archive/zip returns ErrFormat here, before parsing anything
	}

	starts := []int64{base + dirOffset}
	if base > 0 {
		starts = append(starts, dirOffset)
	}
	return starts
}

// countRecords counts the central-directory records in [start, end), stopping
// as soon as it passes max: the question is only "more than max?", and
// answering it must not cost more than the cap allows.
func countRecords(r io.ReaderAt, start, end int64, max int) int {
	if start < 0 || start >= end {
		return 0
	}

	buf := bufio.NewReaderSize(io.NewSectionReader(r, start, end-start), 64<<10)
	var header [centralHeaderLen]byte

	count := 0
	for count <= max {
		if _, err := io.ReadFull(buf, header[:]); err != nil {
			return count
		}
		if binary.LittleEndian.Uint32(header[0:4]) != centralHeaderSig {
			return count
		}
		// File name, extra field and comment, at offsets 28, 30 and 32 of the
		// fixed header. Skipping them is what keeps this allocation-free.
		skip := int(binary.LittleEndian.Uint16(header[28:30])) +
			int(binary.LittleEndian.Uint16(header[30:32])) +
			int(binary.LittleEndian.Uint16(header[32:34]))
		if _, err := buf.Discard(skip); err != nil {
			return count
		}
		count++
	}
	return count
}

// readCentralDir locates and reads the End Of Central Directory record.
//
// archive/zip looks for it in the last 1 KiB and then in the last 65 KiB: the
// record is 22 bytes plus an archive comment of up to 64 KiB, which is why the
// signature has to be searched for backwards instead of read from a fixed
// offset. The same two windows are used here so that both agree on which
// candidate signature is the real one.
func readCentralDir(r io.ReaderAt, size int64) (centralDir, bool) {
	for i, window := range []int64{1024, 65 * 1024} {
		if window > size {
			window = size
		}
		buf := make([]byte, window)
		if _, err := r.ReadAt(buf, size-window); err != nil && !errors.Is(err, io.EOF) {
			return centralDir{}, false
		}

		p := findEOCD(buf)
		if p < 0 {
			if i == 1 || window == size {
				return centralDir{}, false
			}
			continue
		}
		return parseEOCD(r, buf[p:], size-window+int64(p))
	}
	return centralDir{}, false
}

// findEOCD scans backwards for the record's signature, exactly as archive/zip
// does — including treating a comment length that does not account for the
// remaining bytes as "no record here" rather than as an error.
func findEOCD(b []byte) int {
	for i := len(b) - eocdLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(b[i:i+4]) != eocdSignature {
			continue
		}
		if n := int(binary.LittleEndian.Uint16(b[i+eocdLen-2 : i+eocdLen])); n+eocdLen+i > len(b) {
			return -1
		}
		return i
	}
	return -1
}

func parseEOCD(r io.ReaderAt, buf []byte, at int64) (centralDir, bool) {
	dir := centralDir{
		end:     at,
		records: uint64(binary.LittleEndian.Uint16(buf[10:12])),
		size:    uint64(binary.LittleEndian.Uint32(buf[12:16])),
		offset:  uint64(binary.LittleEndian.Uint32(buf[16:20])),
	}

	// The sentinels that mean "the real values are in the zip64 record". The
	// middle one compares a 32-bit field against 0xffff rather than
	// 0xffffffff: that is archive/zip's own condition, and this has to agree
	// with it about when the zip64 record wins.
	if dir.records != 0xffff && dir.size != 0xffff && dir.offset != 0xffffffff {
		return dir, true
	}

	dir64, found, err := zip64Dir(r, at)
	switch {
	case err != nil:
		return centralDir{}, false // archive/zip fails on this too, before parsing
	case found:
		return dir64, true
	default:
		return dir, true
	}
}

// zip64Dir reads the zip64 directory the 32-bit record pointed at. Not finding
// the locator is normal — the sentinel values are also legal literal values —
// and leaves the 32-bit numbers in force.
func zip64Dir(r io.ReaderAt, eocdAt int64) (centralDir, bool, error) {
	loc := eocdAt - eocd64LocLen
	if loc < 0 {
		return centralDir{}, false, nil
	}
	buf := make([]byte, eocd64LocLen)
	if _, err := r.ReadAt(buf, loc); err != nil {
		return centralDir{}, false, err
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != eocd64LocSig ||
		binary.LittleEndian.Uint32(buf[4:8]) != 0 ||
		binary.LittleEndian.Uint32(buf[16:20]) != 1 {
		return centralDir{}, false, nil
	}

	at := binary.LittleEndian.Uint64(buf[8:16])
	if at > math.MaxInt64 {
		return centralDir{}, false, zip.ErrFormat
	}
	record := make([]byte, eocd64Len)
	if _, err := r.ReadAt(record, int64(at)); err != nil { // #nosec G115 -- bounded just above
		return centralDir{}, false, err
	}
	if binary.LittleEndian.Uint32(record[0:4]) != eocd64Sig {
		return centralDir{}, false, zip.ErrFormat
	}

	return centralDir{
		end:     int64(at), // #nosec G115 -- bounded against MaxInt64 above
		records: binary.LittleEndian.Uint64(record[32:40]),
		size:    binary.LittleEndian.Uint64(record[40:48]),
		offset:  binary.LittleEndian.Uint64(record[48:56]),
	}, true, nil
}
