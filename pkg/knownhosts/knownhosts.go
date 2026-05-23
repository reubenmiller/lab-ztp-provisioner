// Package knownhosts provides helpers for modifying SSH known_hosts files.
package knownhosts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Remove runs `ssh-keygen -R <hostname> -f <file>` to remove all entries for
// the given hostname from the known_hosts file. If file is empty or contains
// only "~/.ssh/known_hosts", the user's default known_hosts path is used.
//
// ssh-keygen creates a <file>.old backup automatically. If the file does not
// exist, ssh-keygen exits cleanly (no error is returned).
//
// An error is returned if the ssh-keygen binary cannot be found or exits
// non-zero. Callers in the server should treat this as a warning rather than
// a fatal error.
func Remove(file, hostname string) error {
	if hostname == "" {
		return fmt.Errorf("knownhosts: hostname must not be empty")
	}

	resolved, err := resolvePath(file)
	if err != nil {
		return fmt.Errorf("knownhosts: resolve path: %w", err)
	}

	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return fmt.Errorf("knownhosts: ssh-keygen not found in PATH: %w", err)
	}

	cmd := exec.Command(sshKeygen, "-R", hostname, "-f", resolved)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("knownhosts: ssh-keygen -R %q: %w: %s", hostname, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// resolvePath expands a leading ~ to the current user's home directory and
// returns an absolute path. If file is empty, the default ~/.ssh/known_hosts
// is returned.
func resolvePath(file string) (string, error) {
	if file == "" {
		file = "~/.ssh/known_hosts"
	}
	if strings.HasPrefix(file, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(home, file[2:])
	}
	return filepath.Clean(file), nil
}
