package web

import (
	"errors"
	"io/fs"
	"os"
)

// DirFS returns an fs.FS rooted at the given on-disk directory. The
// caller is expected to have validated that dir exists; this just
// wraps os.DirFS with an index-presence check so the SPA handler can
// emit a sensible warning when the operator points web.dir at an
// empty directory.
//
// Returns an error if dir cannot be stat'd or doesn't contain an
// index.html — both signal a misconfigured deployment that should
// fail fast at startup rather than silently 404 every request.
func DirFS(dir string) (fs.FS, error) {
	if dir == "" {
		return nil, errors.New("web.dir is empty")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, errors.New("web.dir is not a directory: " + dir)
	}
	f := os.DirFS(dir)
	if !hasIndex(f) {
		return nil, errors.New("web.dir does not contain index.html: " + dir)
	}
	return f, nil
}
