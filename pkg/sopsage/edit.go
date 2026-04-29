package sopsage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// Edit performs the standard "decrypt → spawn editor → re-encrypt" loop
// against an existing SOPS-age file. Behaviour mirrors `sops <file>`:
//
//   - The plaintext is written to a 0600 tempfile in the same directory
//     as the target so the post-edit rename is atomic across filesystems.
//   - The editor is invoked synchronously; we re-read the tempfile after
//     it exits regardless of exit code, matching what `sops` does.
//   - The pre-existing EncryptionRules are lifted from the file's sops:
//     block so the same set of keys is re-sealed; recipients can be
//     extended (never reduced) by the caller.
//
// editor is the command-line invocation (e.g. "vim", "code -w"). When
// empty, $EDITOR is used; falling back to "vi" matches sops upstream.
//
// Caller must have an identity capable of decrypting the file. The
// recipients list is what the new (re-sealed) file will be encrypted for
// — typically the union of the existing recipients and any added by the
// operator. We deliberately do NOT default to "preserve existing
// recipients only" because rotation would then be impossible without
// dropping back to `sops`.
func Edit(path string, identities []age.Identity, recipients []age.Recipient, editor string) error {
	if editor == "" {
		editor = os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
	}

	encBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	rules, err := readRules(encBytes)
	if err != nil {
		return err
	}

	plain, err := Decrypt(encBytes, identities)
	if err != nil {
		return fmt.Errorf("decrypt %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".sopsage-edit-*.yaml")
	if err != nil {
		return fmt.Errorf("tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup: succeeded edits will rename a *different*
	// file over the target, so removing tmpPath afterwards is safe.
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod tempfile: %w", err)
	}
	if _, err := tmp.Write(plain); err != nil {
		tmp.Close()
		return fmt.Errorf("write tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tempfile: %w", err)
	}

	if err := runEditor(editor, tmpPath); err != nil {
		return err
	}

	edited, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("read edited tempfile: %w", err)
	}
	// Bail if the operator left the file unchanged — running the full
	// re-seal would still produce a different ciphertext (fresh nonce,
	// fresh data key) which would defeat audit-log usefulness.
	if string(edited) == string(plain) {
		return nil
	}

	out, err := Encrypt(edited, recipients, rules)
	if err != nil {
		return fmt.Errorf("re-encrypt: %w", err)
	}

	// Atomic-replace the original via a fresh tempfile so a crash leaves
	// either the old or new file intact, never a half-written one.
	finalTmp, err := os.CreateTemp(filepath.Dir(path), ".sopsage-final-*.yaml")
	if err != nil {
		return fmt.Errorf("final tempfile: %w", err)
	}
	finalPath := finalTmp.Name()
	if _, err := finalTmp.Write(out); err != nil {
		finalTmp.Close()
		os.Remove(finalPath)
		return fmt.Errorf("write final: %w", err)
	}
	if err := finalTmp.Close(); err != nil {
		os.Remove(finalPath)
		return fmt.Errorf("close final: %w", err)
	}
	// Mirror the original file's mode so we don't surprise operators
	// who have it locked-down to 0600.
	if info, err := os.Stat(path); err == nil {
		_ = os.Chmod(finalPath, info.Mode())
	}
	if err := os.Rename(finalPath, path); err != nil {
		os.Remove(finalPath)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// runEditor splits the editor command on whitespace (so callers can pass
// "code -w" or similar), appends the path argument, and waits for exit.
// We don't try to be clever about quoting because the operator owns the
// $EDITOR string — same trust model as sops.
func runEditor(editorCmd, path string) error {
	parts := strings.Fields(editorCmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty editor command")
	}
	args := append(parts[1:], path)
	cmd := exec.Command(parts[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %q exited with error: %w", editorCmd, err)
	}
	return nil
}

// readRules extracts the EncryptionRules from an existing sops file so a
// re-seal preserves the operator's original key-selection policy. We
// reuse extractSOPSMeta indirectly (via a fresh decode) rather than
// poking at the yaml.Node tree a second time.
func readRules(encBytes []byte) (EncryptionRules, error) {
	if !IsEncrypted(encBytes) {
		return EncryptionRules{}, ErrNotEncrypted
	}
	// We only need the metadata; parse with a minimal struct.
	type meta struct {
		EncryptedRegex    string `yaml:"encrypted_regex"`
		UnencryptedRegex  string `yaml:"unencrypted_regex"`
		EncryptedSuffix   string `yaml:"encrypted_suffix"`
		UnencryptedSuffix string `yaml:"unencrypted_suffix"`
	}
	type wrapper struct {
		Sops meta `yaml:"sops"`
	}
	var w wrapper
	if err := yaml.Unmarshal(encBytes, &w); err != nil {
		return EncryptionRules{}, fmt.Errorf("read rules: %w", err)
	}
	return EncryptionRules{
		EncryptedRegex:    w.Sops.EncryptedRegex,
		UnencryptedRegex:  w.Sops.UnencryptedRegex,
		EncryptedSuffix:   w.Sops.EncryptedSuffix,
		UnencryptedSuffix: w.Sops.UnencryptedSuffix,
	}, nil
}
