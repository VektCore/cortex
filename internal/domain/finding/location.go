package finding

import (
	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/domain/shared"
)

// Location is an immutable value object describing where a finding lives
// in source code. Coordinates are 1-based (line/col), matching SARIF.
type Location struct {
	file      string
	startLine int
	endLine   int
	startCol  int
	endCol    int
}

// LocationInput is the constructor argument struct. Using a struct avoids
// long positional argument lists.
type LocationInput struct {
	File      string
	StartLine int
	EndLine   int
	StartCol  int
	EndCol    int
}

// NewLocation validates input and returns a Location. EndLine defaults to
// StartLine when zero; columns default to 1 when zero.
func NewLocation(in LocationInput) mo.Result[Location] {
	if in.File == "" {
		return shared.Err[Location](shared.NewDomainError(
			"LOCATION_NO_FILE", "file is required"))
	}
	if in.StartLine < 1 {
		return shared.Err[Location](shared.NewDomainError(
			"LOCATION_BAD_LINE", "startLine must be ≥ 1"))
	}
	end := in.EndLine
	if end < in.StartLine {
		end = in.StartLine
	}
	startCol := in.StartCol
	if startCol < 1 {
		startCol = 1
	}
	endCol := in.EndCol
	if endCol < startCol {
		endCol = startCol
	}
	return shared.Ok(Location{
		file:      in.File,
		startLine: in.StartLine,
		endLine:   end,
		startCol:  startCol,
		endCol:    endCol,
	})
}

// MustNewLocation panics on invalid input. Test helper only.
func MustNewLocation(in LocationInput) Location {
	r := NewLocation(in)
	v, err := r.Get()
	if err != nil {
		panic(err)
	}
	return v
}

func (l Location) File() string   { return l.file }
func (l Location) StartLine() int { return l.startLine }
func (l Location) EndLine() int   { return l.endLine }
func (l Location) StartCol() int  { return l.startCol }
func (l Location) EndCol() int    { return l.endCol }

// Equal reports value equality.
func (l Location) Equal(o Location) bool {
	return l.file == o.file &&
		l.startLine == o.startLine &&
		l.endLine == o.endLine &&
		l.startCol == o.startCol &&
		l.endCol == o.endCol
}
