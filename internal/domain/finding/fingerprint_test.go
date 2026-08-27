package finding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vektcore/cortex/internal/domain/finding"
)

func TestFingerprint_Deterministic(t *testing.T) {
	t.Parallel()
	loc := finding.MustNewLocation(finding.LocationInput{
		File: "src/db.go", StartLine: 42,
	})
	a := finding.NewFingerprint("rule.x", loc, "exec(query)")
	b := finding.NewFingerprint("rule.x", loc, "exec(query)")
	assert.Equal(t, a, b)
	assert.Len(t, string(a), finding.FingerprintLength)
}

func TestFingerprint_ChangesWithRule(t *testing.T) {
	t.Parallel()
	loc := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1})
	a := finding.NewFingerprint("rule.x", loc, "code")
	b := finding.NewFingerprint("rule.y", loc, "code")
	assert.NotEqual(t, a, b)
}

func TestFingerprint_ChangesWithFile(t *testing.T) {
	t.Parallel()
	la := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1})
	lb := finding.MustNewLocation(finding.LocationInput{File: "b.go", StartLine: 1})
	a := finding.NewFingerprint("r", la, "code")
	b := finding.NewFingerprint("r", lb, "code")
	assert.NotEqual(t, a, b)
}

func TestFingerprint_ChangesWithLine(t *testing.T) {
	t.Parallel()
	la := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1})
	lb := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 2})
	a := finding.NewFingerprint("r", la, "code")
	b := finding.NewFingerprint("r", lb, "code")
	assert.NotEqual(t, a, b)
}

func TestFingerprint_InvariantToWhitespace(t *testing.T) {
	t.Parallel()
	loc := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1})
	a := finding.NewFingerprint("r", loc, "if x { run() }")
	b := finding.NewFingerprint("r", loc, "if   x  {  run()  }")
	c := finding.NewFingerprint("r", loc, "if\tx\n{run()}")
	assert.Equal(t, a, b, "extra spaces should not change fingerprint")
	assert.Equal(t, a, c, "tabs/newlines should not change fingerprint")
}

func TestFingerprint_InvariantToCase(t *testing.T) {
	t.Parallel()
	loc := finding.MustNewLocation(finding.LocationInput{File: "a.go", StartLine: 1})
	a := finding.NewFingerprint("r", loc, "EXEC(query)")
	b := finding.NewFingerprint("r", loc, "exec(query)")
	assert.Equal(t, a, b)
}
