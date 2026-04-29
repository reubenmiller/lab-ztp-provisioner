// Package web serves the SvelteKit single-page admin app, either from
// an embedded fs.FS (the default — assets baked into the binary at
// build time) or from an external directory (operator-supplied via
// `web.dir` in the config, useful for local development against a
// running ztp-server without rebuilding it).
//
// The embed source is internal/server/web/dist, populated by
// `just web-build` which runs the Vite build under web/ and copies
// the output into this package. A committed .gitkeep keeps the
// directory present on a fresh clone so `go build` succeeds even
// before the SPA has been built; in that case the embedded FS is
// effectively empty and the SPA handler returns a placeholder page
// pointing the operator at the build command.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// EmbeddedFS returns the SPA assets baked into the binary, rooted at
// the dist/ subdirectory so callers can index files as if dist were
// the SPA root (i.e. "index.html", not "dist/index.html"). Returns
// nil if the embed is empty (no files apart from the .gitkeep
// scaffold) — callers should fall through to a placeholder handler.
func EmbeddedFS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil
	}
	if !hasIndex(sub) {
		return nil
	}
	return sub
}

// hasIndex reports whether the FS contains an index.html at its root.
// Used both to decide if the embed has real assets and to short-circuit
// the SPA handler's index-fallback logic on a totally empty FS.
func hasIndex(f fs.FS) bool {
	if f == nil {
		return false
	}
	_, err := fs.Stat(f, "index.html")
	return err == nil
}
