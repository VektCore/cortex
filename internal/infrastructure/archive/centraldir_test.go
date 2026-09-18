package archive

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// directoryImage builds an archive that is only a central directory: the
// records, then the End Of Central Directory record describing them. It can
// lie the way an attacker would, which is the point of the bound.
type directoryImage struct {
	records         int
	declaredRecords int    // 0 means "the real number"
	declaredSize    uint32 // 0 means "the real size"
	comment         int    // bytes of archive comment after the record
	stub            int    // bytes prepended, as a self-extracting archive has
}

func (i directoryImage) bytes() []byte {
	const recordLen = centralHeaderLen + 1

	record := make([]byte, recordLen)
	binary.LittleEndian.PutUint32(record[0:4], centralHeaderSig)
	binary.LittleEndian.PutUint16(record[28:30], 1)
	record[centralHeaderLen] = 'f'

	out := bytes.Repeat([]byte("S"), i.stub)
	for n := 0; n < i.records; n++ {
		out = append(out, record...)
	}

	declaredRecords, declaredSize := i.declaredRecords, i.declaredSize
	if declaredRecords == 0 {
		declaredRecords = i.records
	}
	if declaredSize == 0 {
		declaredSize = uint32(recordLen * i.records)
	}

	eocd := make([]byte, eocdLen)
	binary.LittleEndian.PutUint32(eocd[0:4], eocdSignature)
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(declaredRecords))
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(declaredRecords))
	binary.LittleEndian.PutUint32(eocd[12:16], declaredSize)
	binary.LittleEndian.PutUint32(eocd[16:20], 0)
	binary.LittleEndian.PutUint16(eocd[20:22], uint16(i.comment))

	out = append(out, eocd...)
	return append(out, bytes.Repeat([]byte("."), i.comment)...)
}

// These go at the bound directly, not through ExtractZip: the extractor also
// re-checks the count after archive/zip has parsed the directory, so an
// end-to-end test cannot tell which of the two refused the archive — and the
// whole point of the change is that the first one does.
func TestBoundEntryCount(t *testing.T) {
	t.Parallel()

	cases := map[string]directoryImage{
		// The record sits behind 40 KiB of comment, past the first window the
		// signature is searched in. Read from a fixed offset instead and the
		// directory is never found, so nothing is ever counted.
		"behind an archive comment": {records: 8, comment: 40_000},
		// A self-extracting stub shifts the whole archive, so the declared
		// offset no longer matches where the directory really is.
		"behind a self-extracting stub": {records: 8, stub: 4096},
		// The bypass the second candidate offset exists for: declare a
		// one-record directory at the end while packing every record from byte
		// zero. archive/zip finds a valid header at the declared offset and
		// reads all of them from there.
		"relocated to the declared offset": {records: 8, declaredRecords: 1, declaredSize: centralHeaderLen + 1},
	}

	for name, image := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := image.bytes()
			r := bytes.NewReader(raw)

			require.ErrorIs(t, boundEntryCount(r, int64(len(raw)), 4), ErrTooManyEntries)
			assert.NoError(t, boundEntryCount(r, int64(len(raw)), 8))
		})
	}
}

// Not every file is a zip. Anything the record cannot be read out of is left
// to archive/zip, which rejects it before it parses a single record — but the
// bound must not mistake it for an empty directory it has checked.
func TestBoundEntryCount_DefersWhenThereIsNoRecord(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string][]byte{
		"empty":      {},
		"too short":  []byte("PK"),
		"not a zip":  bytes.Repeat([]byte("not a zip at all"), 64),
		"truncated":  directoryImage{records: 8}.bytes()[:100],
		"no records": directoryImage{}.bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.NoError(t, boundEntryCount(bytes.NewReader(raw), int64(len(raw)), 4))
		})
	}
}
