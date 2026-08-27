package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vektcore/cortex/internal/domain/finding"
)

func TestNewLocation_Valid(t *testing.T) {
	t.Parallel()
	r := finding.NewLocation(finding.LocationInput{
		File: "src/a.go", StartLine: 10, EndLine: 12, StartCol: 5, EndCol: 8,
	})
	l, err := r.Get()
	require.NoError(t, err)
	assert.Equal(t, "src/a.go", l.File())
	assert.Equal(t, 10, l.StartLine())
	assert.Equal(t, 12, l.EndLine())
	assert.Equal(t, 5, l.StartCol())
	assert.Equal(t, 8, l.EndCol())
}

func TestNewLocation_DefaultsAndCoercions(t *testing.T) {
	t.Parallel()
	r := finding.NewLocation(finding.LocationInput{
		File: "a.go", StartLine: 5,
	})
	l, err := r.Get()
	require.NoError(t, err)
	assert.Equal(t, 5, l.EndLine(), "EndLine defaults to StartLine")
	assert.Equal(t, 1, l.StartCol(), "StartCol defaults to 1")
	assert.Equal(t, 1, l.EndCol(), "EndCol defaults to StartCol")
}

func TestNewLocation_Invalid(t *testing.T) {
	t.Parallel()
	cases := []finding.LocationInput{
		{File: "", StartLine: 1},
		{File: "a.go", StartLine: 0},
		{File: "a.go", StartLine: -3},
	}
	for _, in := range cases {
		_, err := finding.NewLocation(in).Get()
		assert.Error(t, err, "input=%+v", in)
	}
}

func TestLocation_Equal(t *testing.T) {
	t.Parallel()
	a := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1})
	b := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1})
	c := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 2})
	assert.True(t, a.Equal(b))
	assert.False(t, a.Equal(c))
}
