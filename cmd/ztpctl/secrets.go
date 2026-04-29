// secrets.go — `ztpctl secrets …` subcommand suite.
//
// Operates on SOPS-age-encrypted YAML files using the in-process
// pkg/sopsage library. Recipients default to whatever the server's
// /v1/admin/profiles/encryption-key endpoint returns; operators can
// override with --recipient flags or by editing the local recipients
// file at $HOME/.config/ztp/age_recipients.
//
// Identities (private keys) are loaded from --age-key-file, falling
// back to $SOPS_AGE_KEY_FILE, then ~/.config/ztp/age_key.txt — so the
// command works without flags when set up via `ztp-server` writing the
// key alongside its own data dir.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/sopsage"
)

const secretsUsage = `secrets seal <file> [--regex <re>] [--recipient <age1…>]…
secrets edit <file>   [--age-key-file <path>] [--recipient <age1…>]…
secrets set  <file> <yaml.path> <value> [--recipient <age1…>]…
secrets reveal <file> [--age-key-file <path>] --yes-show-secrets
secrets encrypt <value-or-->  [--recipient <age1…>]… [--type str|int|float|bool|bytes]`

// runSecrets is the entry point dispatched from main.go.
func runSecrets(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, secretsUsage)
		os.Exit(2)
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "seal":
		secretsSeal(rest)
	case "edit":
		secretsEdit(rest)
	case "set":
		secretsSet(rest)
	case "reveal":
		secretsReveal(rest)
	case "encrypt":
		secretsEncrypt(rest)
	default:
		fmt.Fprintln(os.Stderr, secretsUsage)
		os.Exit(2)
	}
}

// secretsFlags is the shared option struct extracted from a subcommand's
// argv. We parse by hand rather than reach for cobra/pflag to stay
// consistent with the existing flat-dispatch ztpctl style.
type secretsFlags struct {
	regex       string
	recipients  []string
	ageKeyFile  string
	allowSecret bool
	leafType    string
	positional  []string
}

func parseSecretsFlags(args []string) secretsFlags {
	var f secretsFlags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--regex":
			i++
			if i < len(args) {
				f.regex = args[i]
			}
		case "--recipient":
			i++
			if i < len(args) {
				f.recipients = append(f.recipients, args[i])
			}
		case "--age-key-file":
			i++
			if i < len(args) {
				f.ageKeyFile = args[i]
			}
		case "--yes-show-secrets":
			f.allowSecret = true
		case "--type":
			i++
			if i < len(args) {
				f.leafType = args[i]
			}
		default:
			f.positional = append(f.positional, args[i])
		}
	}
	return f
}

// resolveRecipients gathers age recipients in priority order:
//  1. explicit --recipient flags (operator-specified, highest priority);
//  2. ~/.config/ztp/age_recipients (one recipient per line);
//  3. server-advertised recipients via /v1/admin/profiles/encryption-key.
//
// The union is deduplicated and parsed; an empty result is fatal because
// a file with no recipients is unrecoverable.
func resolveRecipients(extra []string) ([]age.Recipient, []string, error) {
	seen := map[string]struct{}{}
	var strs []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		strs = append(strs, s)
	}
	for _, s := range extra {
		add(s)
	}
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".config", "ztp", "age_recipients")
		if data, err := os.ReadFile(path); err == nil {
			sc := bufio.NewScanner(strings.NewReader(string(data)))
			for sc.Scan() {
				add(strings.TrimSpace(sc.Text()))
			}
		}
	}
	for _, s := range fetchServerRecipients() {
		add(s)
	}
	if len(strs) == 0 {
		return nil, nil, errors.New("no recipients: use --recipient or set ZTP_SERVER/ZTP_TOKEN so the server can supply its public key")
	}
	rcps := make([]age.Recipient, 0, len(strs))
	for _, s := range strs {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, nil, fmt.Errorf("recipient %q: %w", s, err)
		}
		rcps = append(rcps, r)
	}
	return rcps, strs, nil
}

// fetchServerRecipients calls /v1/admin/profiles/encryption-key. Failures
// (no ZTP_SERVER set, network error, server lacking an age key) are
// silently dropped so operator-managed setups still work — explicit
// --recipient flags then carry the configuration.
func fetchServerRecipients() []string {
	server := os.Getenv("ZTP_SERVER")
	if server == "" {
		return nil
	}
	req, err := http.NewRequest("GET", server+"/v1/admin/profiles/encryption-key", nil)
	if err != nil {
		return nil
	}
	if t := os.Getenv("ZTP_TOKEN"); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil
	}
	var body struct {
		Recipients []string `json:"recipients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	return body.Recipients
}

// loadIdentities resolves a private key for decrypt operations from the
// first source that exists: explicit flag, $SOPS_AGE_KEY_FILE,
// ~/.config/ztp/age_key.txt. Returns a nicer error than age would on its
// own when nothing is configured.
func loadIdentities(flagPath string) ([]age.Identity, error) {
	candidates := []string{flagPath, os.Getenv("SOPS_AGE_KEY_FILE")}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "ztp", "age_key.txt"))
	}
	var lastErr error
	for _, p := range candidates {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			if !os.IsNotExist(err) {
				lastErr = err
			}
			continue
		}
		ids, err := age.ParseIdentities(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if len(ids) > 0 {
			return ids, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no age private key found; set --age-key-file, $SOPS_AGE_KEY_FILE, or write one to ~/.config/ztp/age_key.txt")
}

// secretsSeal — first-time encryption of a plain YAML file. Two modes:
//   - --regex: encrypt every leaf whose key matches the regex.
//   - default: encrypt only leaves the user has tagged with !encrypt
//     (handled by sopsage.PrepareTaggedSeal).
func secretsSeal(args []string) {
	f := parseSecretsFlags(args)
	if len(f.positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secrets seal <file> [--regex <re>] [--recipient <age1…>]…")
		os.Exit(2)
	}
	path := f.positional[0]
	plain, err := os.ReadFile(path)
	must(err)
	rcps, _, err := resolveRecipients(f.recipients)
	must(err)

	var rules sopsage.EncryptionRules
	if f.regex != "" {
		rules = sopsage.EncryptionRules{EncryptedRegex: f.regex}
	} else {
		// Tag-driven seal: strip !encrypt tags, derive a regex matching
		// just those keys, and re-encrypt the now-clean YAML.
		clean, derived, err := sopsage.PrepareTaggedSeal(plain)
		must(err)
		plain = clean
		rules = derived
		if rules.EncryptedRegex == "" {
			fail(fmt.Errorf("no leaves tagged %q and no --regex given; nothing to encrypt", sopsage.SealTag))
		}
	}
	out, err := sopsage.Encrypt(plain, rcps, rules)
	must(err)
	must(atomicWrite(path, out))
}

func secretsEdit(args []string) {
	f := parseSecretsFlags(args)
	if len(f.positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secrets edit <file> [--age-key-file <path>] [--recipient <age1…>]…")
		os.Exit(2)
	}
	ids, err := loadIdentities(f.ageKeyFile)
	must(err)
	// For edits we re-encrypt to whatever recipients we can resolve so a
	// shared file stays decryptable for everyone configured.
	rcps, _, err := resolveRecipients(f.recipients)
	must(err)
	must(sopsage.Edit(f.positional[0], ids, rcps, ""))
}

func secretsSet(args []string) {
	f := parseSecretsFlags(args)
	if len(f.positional) != 3 {
		fmt.Fprintln(os.Stderr, "usage: secrets set <file> <yaml.path> <value> [--recipient <age1…>]…")
		os.Exit(2)
	}
	// Implementation deferred: requires a path-walker on yaml.Node.
	// `secrets edit` covers the same use case interactively; if there's
	// no demand for the non-interactive variant we'd rather not maintain
	// a bespoke YAML-path mini-language.
	fail(errors.New("secrets set: not implemented; use `secrets edit` for now"))
}

func secretsReveal(args []string) {
	f := parseSecretsFlags(args)
	if len(f.positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secrets reveal <file> [--age-key-file <path>] --yes-show-secrets")
		os.Exit(2)
	}
	if !f.allowSecret {
		fail(errors.New("refusing to print plaintext secrets without --yes-show-secrets"))
	}
	ids, err := loadIdentities(f.ageKeyFile)
	must(err)
	enc, err := os.ReadFile(f.positional[0])
	must(err)
	plain, err := sopsage.Decrypt(enc, ids)
	must(err)
	_, _ = os.Stdout.Write(plain)
}

func secretsEncrypt(args []string) {
	f := parseSecretsFlags(args)
	if len(f.positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secrets encrypt <value-or-->  [--recipient <age1…>]… [--type str|int|float|bool|bytes]")
		os.Exit(2)
	}
	// secrets encrypt is a debug aid: it produces a stand-alone ENC[…]
	// blob that is NOT pasteable into a SOPS file (data key differs).
	// Documented in the plan; we surface the limitation in stderr to
	// avoid surprising operators who might paste the output and hit a
	// MAC failure later.
	fmt.Fprintln(os.Stderr, "warning: this blob has its own data key and cannot be pasted into a SOPS file; use `secrets edit` for that.")
	value := f.positional[0]
	if value == "-" {
		b, err := io.ReadAll(os.Stdin)
		must(err)
		value = strings.TrimRight(string(b), "\n")
	}
	// secrets encrypt currently can't produce a "valid stand-alone token"
	// without exposing AES primitives that aren't part of the public
	// sopsage API. Surface this limitation explicitly rather than ship a
	// blob that doesn't survive `secrets reveal` round-tripping.
	_ = f.leafType
	fail(errors.New("secrets encrypt: not implemented; the standalone-blob format is debug-only and disabled until a use case appears"))
}

// atomicWrite writes data to a sibling tempfile and renames over path.
// Mode is preserved when the target exists, otherwise defaults to 0600
// (safe default for files holding ciphertext + sops metadata).
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ztpctl-*.yaml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode()
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

func must(err error) {
	if err != nil {
		fail(err)
	}
}
