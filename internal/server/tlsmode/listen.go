package tlsmode

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/paths"
)

// Options bundles the runtime knobs that aren't expressible via the
// Mode enum alone. Callers populate it from config + paths.
type Options struct {
	// CertFile, KeyFile are the on-disk paths consulted when Mode == Cert.
	CertFile string
	KeyFile  string

	// SelfSignedCacheDir is where generated self-signed material is
	// cached. Empty falls back to paths.TLSCacheDir().
	SelfSignedCacheDir string

	// Hostnames are added as DNS SANs when Mode == SelfSigned.
	Hostnames []string

	Logger *slog.Logger
}

// Serve binds the listener and runs srv.Serve / srv.ServeTLS as
// appropriate for the chosen Mode. It blocks until the underlying
// server returns; callers typically run it in a goroutine and watch
// the returned error.
//
// The listener is supplied by the caller (already bound) so the
// caller can read its actual address before Serve takes ownership —
// important when binding to ":0" for an ephemeral port.
func Serve(srv *http.Server, listener net.Listener, mode Mode, opts Options) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	switch mode {
	case Off:
		return srv.Serve(listener)

	case Cert:
		if opts.CertFile == "" || opts.KeyFile == "" {
			return errors.New("tlsmode: Mode=cert requires CertFile and KeyFile")
		}
		logger.Info("tls: serving with operator-supplied cert", "cert", opts.CertFile)
		return srv.ServeTLS(listener, opts.CertFile, opts.KeyFile)

	case SelfSigned:
		dir := opts.SelfSignedCacheDir
		if dir == "" {
			dir = paths.TLSCacheDir()
		}
		cert, err := LoadOrGenerate(SelfSignedConfig{
			CacheDir:  dir,
			Hostnames: opts.Hostnames,
		})
		if err != nil {
			return fmt.Errorf("tlsmode: self-signed: %w", err)
		}
		logger.Info("tls: serving with self-signed cert (browsers will warn)",
			"cache_dir", dir, "expires", cert.Leaf.NotAfter)
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
		// ServeTLS with empty cert/key paths uses srv.TLSConfig — see net/http docs.
		return srv.ServeTLS(listener, "", "")

	default:
		return fmt.Errorf("tlsmode: unsupported mode %q", mode)
	}
}
