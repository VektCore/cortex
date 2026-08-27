package git

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The parser is what makes "gate only on the lines this branch changed"
// trustworthy, so it is tested directly against real diff output shapes.
func TestParseUnifiedDiff(t *testing.T) {
	t.Parallel()

	diff := `diff --git a/app/db.py b/app/db.py
index 1111111..2222222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -12,0 +13,3 @@ def get_user(uid):
+    query = "SELECT " + uid
+    return conn.execute(query)
+
@@ -40 +43 @@ def other():
-    old
+    new
diff --git a/removed.py b/removed.py
deleted file mode 100644
--- a/removed.py
+++ /dev/null
@@ -1,5 +0,0 @@
`

	changed := parseUnifiedDiff(diff)

	assert.Len(t, changed, 1, "a deleted file cannot hold a finding")
	ranges := changed["app/db.py"]
	assert.Equal(t, 2, len(ranges))
	assert.Equal(t, 13, ranges[0].Start)
	assert.Equal(t, 15, ranges[0].End)
	assert.Equal(t, 43, ranges[1].Start)
	assert.Equal(t, 43, ranges[1].End, "a hunk with no length covers one line")
}

func TestParseHunk_PureDeletionIsNotAChange(t *testing.T) {
	t.Parallel()

	_, ok := parseHunk("@@ -10,3 +9,0 @@")
	assert.False(t, ok, "a zero-length destination hunk removed code, it did not add any")

	_, ok = parseHunk("not a hunk header")
	assert.False(t, ok)
}
