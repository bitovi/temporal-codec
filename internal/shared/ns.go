package shared

import "strings"

// ShortName returns the Temporal namespace short name (everything before the
// first '.'), or the name unchanged if no '.' is present.
// Used in both auth (claim matching) and codec (URI template resolution) — the
// two copies must never drift, so they share this function.
func ShortName(ns string) string {
	if i := strings.IndexByte(ns, '.'); i > 0 {
		return ns[:i]
	}
	return ns
}
