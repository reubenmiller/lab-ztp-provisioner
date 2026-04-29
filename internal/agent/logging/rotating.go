package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFile is an io.WriteCloser that caps the on-disk size of a single
// log file. When the current file would grow past MaxBytes, RotatingFile
// closes it, renames it to "<path>.1" (cascading existing backups up to
// MaxBackups), and reopens the original path empty.
//
// Rotation happens *before* a Write that would exceed the threshold, so the
// caller's write lands entirely in the new file — assuming each Write is a
// complete log record (which the stdlib slog handlers guarantee). This keeps
// rotation aligned to record boundaries with no partial-line splits.
//
// MaxBytes <= 0 disables rotation; the file then grows unbounded.
//
// MaxBackups is the maximum number of rotated files kept on disk
// ("<path>.1" through "<path>.<MaxBackups>"). Older backups are deleted on
// rotation. MaxBackups <= 0 means "do not keep any rotated copies" — the
// file is truncated in place once full, which loses history but bounds disk
// use to MaxBytes flat.
type RotatingFile struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
}

// OpenRotating creates the parent directory (mode 0750) if needed, opens
// path in append+create mode (mode 0640), and returns a RotatingFile that
// has counted the file's existing size so it rotates on schedule even
// across agent restarts.
func OpenRotating(path string, maxBytes int64, maxBackups int) (*RotatingFile, error) {
	if path == "" {
		return nil, errors.New("rotating file: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	return &RotatingFile{
		path:       path,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
		file:       f,
		size:       st.Size(),
	}, nil
}

// Write implements io.Writer. It rotates the file when the *next* write
// would exceed MaxBytes, so each individual write lands in a single file —
// useful when callers feed it one complete log record per Write (slog does).
//
// Errors during rotation are logged via the secondary stderr fallback only;
// they never fail the Write itself, because losing the agent's own log
// output is preferable to crashing on a pre-existing disk problem.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxBytes > 0 && r.size+int64(len(p)) > r.maxBytes && r.size > 0 {
		if err := r.rotateLocked(); err != nil {
			fmt.Fprintf(os.Stderr, "ztp-agent: log rotation failed: %v\n", err)
			// Fall through and write to whatever is open — the file may now
			// be in a half-rotated state, but losing one line is better than
			// losing every subsequent line.
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

// Close releases the underlying file. Subsequent Writes return io.ErrClosedPipe.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

// rotateLocked shifts existing backups one slot down (.N is deleted, .(N-1)
// becomes .N, ..., .1 becomes .2) and renames the current file to .1, then
// reopens path. Caller must hold r.mu.
//
// The maxBackups <= 0 case: there are no backups to keep, so we simply
// truncate the current file in place. This bounds total disk use to
// MaxBytes but discards everything older than the cap.
func (r *RotatingFile) rotateLocked() error {
	if r.file == nil {
		return errors.New("rotating file: closed")
	}
	if err := r.file.Close(); err != nil {
		return fmt.Errorf("close before rotate: %w", err)
	}
	r.file = nil

	if r.maxBackups <= 0 {
		// In-place truncate: drop history but bound size at MaxBytes.
		if err := os.Truncate(r.path, 0); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("truncate %s: %w", r.path, err)
		}
	} else {
		// Cascade: .N → discard, .(N-1) → .N, ..., .1 → .2, current → .1
		oldest := backupName(r.path, r.maxBackups)
		_ = os.Remove(oldest) // ignore if missing
		for i := r.maxBackups - 1; i >= 1; i-- {
			from := backupName(r.path, i)
			to := backupName(r.path, i+1)
			if _, err := os.Stat(from); err == nil {
				if err := os.Rename(from, to); err != nil {
					return fmt.Errorf("rotate %s -> %s: %w", from, to, err)
				}
			}
		}
		if err := os.Rename(r.path, backupName(r.path, 1)); err != nil {
			return fmt.Errorf("rotate %s -> .1: %w", r.path, err)
		}
	}

	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("reopen %s after rotate: %w", r.path, err)
	}
	r.file = f
	r.size = 0
	return nil
}

// backupName returns the path used for the n-th rotated copy ("<path>.1",
// "<path>.2", ...). n must be >= 1.
func backupName(path string, n int) string {
	return fmt.Sprintf("%s.%d", path, n)
}

// compile-time assertion: RotatingFile satisfies io.WriteCloser.
var _ io.WriteCloser = (*RotatingFile)(nil)
