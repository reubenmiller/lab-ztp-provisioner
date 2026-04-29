package web

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// placeholderHTML is what the SPA handler serves when no assets are
// available (empty embed and no web.dir). Keeps the operator unstuck
// — a curl to / returns something self-explanatory rather than 404.
const placeholderHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ZTP server</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:42em;margin:4em auto;padding:0 1em;color:#222}code{background:#eee;padding:0.1em 0.3em;border-radius:0.2em}</style>
</head><body>
<h1>ZTP server is running</h1>
<p>The admin SPA is not available. To enable the admin UI, build it
and rebuild the binary:</p>
<pre><code>just web-build
just build</code></pre>
<p>Or point at an external build with <code>web.dir</code> in your config.
The JSON API at <code>/v1/*</code> is unaffected and ready to serve.</p>
</body></html>`

// SPAHandler serves a static-build SvelteKit app and falls back to
// /index.html for any path that doesn't resolve to an asset, matching
// the `fallback: 'index.html'` behaviour that adapter-static produces
// in web/svelte.config.js. Without that rewrite, hard-refreshing on a
// client-side route like /profiles/foo would 404.
//
// The handler intentionally does not serve API paths: anything under
// /v1/, plus /healthz and /readyz, is forwarded to the API handler
// upstream of this. Those paths arriving here would indicate a
// composition bug; they're rejected with 404 instead of dressed up as
// SPA pages so the bug surfaces.
type SPAHandler struct {
	FS fs.FS
}

// NewSPAHandler returns a handler. A nil FS is acceptable and serves
// the placeholder page on every GET — useful for binaries built
// before the SPA was compiled.
func NewSPAHandler(f fs.FS) *SPAHandler {
	return &SPAHandler{FS: f}
}

func (h *SPAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Defence in depth — if api routing misfires and a /v1/* request
	// arrives here, surface it as 404 rather than rendering the SPA
	// shell, which would mask the bug.
	if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		http.NotFound(w, r)
		return
	}
	if h.FS == nil {
		writePlaceholder(w)
		return
	}

	clean := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	if clean == "/" {
		serveFile(w, r, h.FS, "index.html")
		return
	}
	name := strings.TrimPrefix(clean, "/")
	if f, err := h.FS.Open(name); err == nil {
		st, statErr := f.Stat()
		_ = f.Close()
		if statErr == nil && !st.IsDir() {
			serveFile(w, r, h.FS, name)
			return
		}
	}
	// SvelteKit-style SPA fallback: any unknown non-asset path renders
	// /index.html so client-side routing can take over.
	serveFile(w, r, h.FS, "index.html")
}

func serveFile(w http.ResponseWriter, r *http.Request, root fs.FS, name string) {
	f, err := root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		// fs.FS doesn't guarantee Seek; copy via a buffer when needed.
		// Acceptable: SvelteKit assets are small and cacheable.
		w.Header().Set("Content-Type", contentTypeFor(name))
		_, _ = io.Copy(w, f)
		return
	}
	http.ServeContent(w, r, name, st.ModTime(), rs)
}

func writePlaceholder(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, placeholderHTML)
}

// contentTypeFor is a deliberately tiny lookup. Most files SvelteKit
// emits have well-known extensions; net/http's mime.TypeByExtension
// would also work but pulls a larger table than we need.
func contentTypeFor(name string) string {
	switch path.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".woff2":
		return "font/woff2"
	case ".woff":
		return "font/woff"
	default:
		return "application/octet-stream"
	}
}
