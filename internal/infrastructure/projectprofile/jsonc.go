package projectprofile

// tsconfig.json is JSONC, not JSON: TypeScript's own parser accepts // and /*
// */ comments and trailing commas, and `tsc --init` emits a file full of them.
// encoding/json rejects all three, so a hand-edited tsconfig — which is most of
// them — would otherwise read as "no information" and the vendored directory
// would keep being scanned.
//
// This strips the three extensions and hands the result to encoding/json. It is
// not a JSON parser: it only has to know where strings begin and end, so that a
// "//" inside a URL or a Windows path is left alone. Anything it gets wrong
// fails in encoding/json, which is a Note, not an error.

// stripJSONC removes comments and trailing commas from a JSONC document.
func stripJSONC(src []byte) []byte {
	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); {
		switch {
		case src[i] == '"':
			end := endOfString(src, i)
			out = append(out, src[i:end]...)
			i = end
		case isLineComment(src, i):
			i = skipLineComment(src, i)
		case isBlockComment(src, i):
			i = skipBlockComment(src, i)
		default:
			out = append(out, src[i])
			i++
		}
	}
	return dropTrailingCommas(out)
}

func isLineComment(src []byte, i int) bool {
	return src[i] == '/' && i+1 < len(src) && src[i+1] == '/'
}

func isBlockComment(src []byte, i int) bool {
	return src[i] == '/' && i+1 < len(src) && src[i+1] == '*'
}

// endOfString returns the index just past the closing quote of the string
// starting at i. An unterminated string consumes the rest of the input, which
// then fails to parse — the correct outcome for a truncated file.
func endOfString(src []byte, i int) int {
	for j := i + 1; j < len(src); j++ {
		if src[j] == '\\' {
			j++
			continue
		}
		if src[j] == '"' {
			return j + 1
		}
	}
	return len(src)
}

// skipLineComment stops at the newline and keeps it: dropping it could join a
// trailing comment's line to the next one.
func skipLineComment(src []byte, i int) int {
	for i < len(src) && src[i] != '\n' {
		i++
	}
	return i
}

func skipBlockComment(src []byte, i int) int {
	for j := i + 2; j+1 < len(src); j++ {
		if src[j] == '*' && src[j+1] == '/' {
			return j + 2
		}
	}
	return len(src)
}

// dropTrailingCommas removes a comma whose next non-space character closes an
// object or an array. String contents are skipped so a comma inside a value is
// never touched.
func dropTrailingCommas(src []byte) []byte {
	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); {
		if src[i] == '"' {
			end := endOfString(src, i)
			out = append(out, src[i:end]...)
			i = end
			continue
		}
		if src[i] == ',' && closesNext(src, i+1) {
			i++
			continue
		}
		out = append(out, src[i])
		i++
	}
	return out
}

func closesNext(src []byte, i int) bool {
	for ; i < len(src); i++ {
		switch src[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '}', ']':
			return true
		default:
			return false
		}
	}
	return false
}
