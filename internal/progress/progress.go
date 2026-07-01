// Package progress writes a lightweight, single-line progress indicator
// to the given writer (typically os.Stderr). It is intentionally minimal:
// no external dependencies, no cursor tricks beyond a carriage return.
package progress

import (
	"fmt"
	"io"
)

// WriteToolProgress renders a "[stage] done/total (pct%)" line, overwriting
// the previous line via \r. Safe to call frequently; it does not print a
// trailing newline so the next call redraws in place.
func WriteToolProgress(w io.Writer, done, total int, stage string) {
	if total <= 0 {
		return
	}
	if done > total {
		done = total
	}
	pct := float64(done) / float64(total) * 100

	const width = 24
	filled := int(float64(width) * float64(done) / float64(total))
	if filled > width {
		filled = width
	}

	bar := make([]byte, width)
	for i := range bar {
		if i < filled {
			bar[i] = '#'
		} else {
			bar[i] = '-'
		}
	}

	fmt.Fprintf(w, "\r[%s] %s %d/%d (%.0f%%)", stage, string(bar), done, total, pct)
	if done >= total {
		fmt.Fprintln(w)
	}
}
