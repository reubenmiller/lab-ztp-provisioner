// Package sqlitestore implements store.Store backed by a SQLite database.
//
// Uses modernc.org/sqlite (pure-Go) so the server binary stays static and
// CGO-free, simplifying cross-compilation for arm64/armv7 device gateways.
package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Store is a SQLite-backed store. Safe for concurrent use; the underlying
// driver serialises writes.
type Store struct {
	db *sql.DB
}

// Open opens (and migrates) a SQLite database at the given DSN. A typical
// DSN is just a file path, e.g. "/var/lib/ztp/ztp.db".
func Open(dsn string) (*Store, error) {
	// Add WAL mode for better concurrent reader performance.
	if !strings.Contains(dsn, "?") {
		dsn += "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite handles concurrency best with a single writer.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	// Schema-version table tracks applied migrations. We use a simple
	// monotonic counter rather than a full migration framework — the project
	// is young enough that the explicit list below is easier to audit than
	// a generic tool. New migrations append to migrations slice; each is
	// idempotent (CREATE IF NOT EXISTS / ALTER ... ADD COLUMN with try/log).
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("schema_version: %w", err)
	}

	migrations := []struct {
		version int
		stmts   []string
	}{
		{1, []string{
			`CREATE TABLE IF NOT EXISTS devices (
				id          TEXT PRIMARY KEY,
				public_key  TEXT NOT NULL,
				facts       TEXT NOT NULL,
				overrides   TEXT,
				enrolled_at INTEGER NOT NULL,
				last_seen   INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS pending (
				id           TEXT PRIMARY KEY,
				device_id    TEXT NOT NULL,
				public_key   TEXT NOT NULL,
				facts        TEXT NOT NULL,
				fingerprint  TEXT NOT NULL,
				reason       TEXT,
				first_seen   INTEGER NOT NULL,
				last_seen    INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS pending_pubkey ON pending(public_key)`,
			`CREATE TABLE IF NOT EXISTS allowlist (
				device_id   TEXT PRIMARY KEY,
				mac         TEXT,
				serial      TEXT,
				note        TEXT,
				created_at  INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS tokens (
				id          TEXT PRIMARY KEY,
				hash        TEXT NOT NULL UNIQUE,
				device_id   TEXT,
				expires_at  INTEGER,
				uses        INTEGER NOT NULL DEFAULT 0,
				max_uses    INTEGER NOT NULL DEFAULT 0,
				created_at  INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS nonces (
				nonce      TEXT PRIMARY KEY,
				expires_at INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS nonces_exp ON nonces(expires_at)`,
			`CREATE TABLE IF NOT EXISTS audit (
				rowid     INTEGER PRIMARY KEY AUTOINCREMENT,
				at        INTEGER NOT NULL,
				actor     TEXT,
				action    TEXT,
				device_id TEXT,
				details   TEXT
			)`,
		}},
		// v2: provisioning profiles. Adds profile_name to devices, profile to
		// allowlist + tokens, and a profiles table for DB-backed profiles.
		{2, []string{
			`ALTER TABLE devices ADD COLUMN profile_name TEXT`,
			`ALTER TABLE allowlist ADD COLUMN profile TEXT`,
			`ALTER TABLE tokens ADD COLUMN profile TEXT`,
			`CREATE TABLE IF NOT EXISTS profiles (
				name        TEXT PRIMARY KEY,
				description TEXT,
				body        BLOB NOT NULL,
				updated_at  INTEGER NOT NULL,
				updated_by  TEXT
			)`,
		}},
	}

	current, err := s.currentVersion()
	if err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		for _, q := range m.stmts {
			if _, err := s.db.Exec(q); err != nil {
				// ALTER TABLE ADD COLUMN is not idempotent in sqlite; tolerate
				// duplicate-column errors so re-running migrations on a partially
				// applied schema (rare, but possible if a previous run crashed)
				// is safe.
				if strings.Contains(err.Error(), "duplicate column name") {
					continue
				}
				return fmt.Errorf("migrate v%d: %w", m.version, err)
			}
		}
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?,?)`,
			m.version, time.Now().UTC().UnixMilli()); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
	}
	return nil
}

// currentVersion returns the highest applied migration version (0 for a
// fresh database).
func (s *Store) currentVersion() (int, error) {
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// --- Devices --------------------------------------------------------------

func (s *Store) UpsertDevice(ctx context.Context, d *store.Device) error {
	facts, _ := json.Marshal(d.Facts)
	overrides, _ := json.Marshal(d.Overrides)
	enrolled := d.EnrolledAt
	if enrolled.IsZero() {
		enrolled = time.Now().UTC()
	}
	last := d.LastSeen
	if last.IsZero() {
		last = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO devices (id, public_key, facts, overrides, enrolled_at, last_seen, profile_name)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			public_key   = excluded.public_key,
			facts        = excluded.facts,
			overrides    = excluded.overrides,
			last_seen    = excluded.last_seen,
			profile_name = excluded.profile_name`,
		d.ID, d.PublicKey, string(facts), string(overrides), enrolled.UnixMilli(), last.UnixMilli(), nullStr(d.ProfileName))
	return err
}

func (s *Store) GetDevice(ctx context.Context, id string) (*store.Device, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, public_key, facts, overrides, enrolled_at, last_seen, profile_name FROM devices WHERE id = ?`, id)
	return scanDevice(row)
}

func (s *Store) ListDevices(ctx context.Context) ([]store.Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, public_key, facts, overrides, enrolled_at, last_seen, profile_name FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.Device, 0)
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (s *Store) FindDeviceByPublicKey(ctx context.Context, pubkey string) (*store.Device, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, public_key, facts, overrides, enrolled_at, last_seen, profile_name FROM devices WHERE public_key = ?`, pubkey)
	return scanDevice(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDevice(r rowScanner) (*store.Device, error) {
	var d store.Device
	var factsJSON, overridesJSON, profileName sql.NullString
	var enrolled, last int64
	if err := r.Scan(&d.ID, &d.PublicKey, &factsJSON, &overridesJSON, &enrolled, &last, &profileName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if factsJSON.Valid {
		_ = json.Unmarshal([]byte(factsJSON.String), &d.Facts)
	}
	if overridesJSON.Valid && overridesJSON.String != "null" && overridesJSON.String != "" {
		_ = json.Unmarshal([]byte(overridesJSON.String), &d.Overrides)
	}
	d.ProfileName = profileName.String
	d.EnrolledAt = time.UnixMilli(enrolled).UTC()
	d.LastSeen = time.UnixMilli(last).UTC()
	return &d, nil
}

// --- Pending --------------------------------------------------------------

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	return err
}

func (s *Store) CreatePending(ctx context.Context, p *store.PendingRequest) error {
	facts, _ := json.Marshal(p.Facts)
	first := p.FirstSeen
	if first.IsZero() {
		first = time.Now().UTC()
	}
	last := p.LastSeen
	if last.IsZero() {
		last = first
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pending (id, device_id, public_key, facts, fingerprint, reason, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			facts       = excluded.facts,
			fingerprint = excluded.fingerprint,
			reason      = excluded.reason,
			last_seen   = excluded.last_seen`,
		p.ID, p.DeviceID, p.PublicKey, string(facts), p.Fingerprint, p.Reason,
		first.UnixMilli(), last.UnixMilli())
	return err
}

func (s *Store) GetPending(ctx context.Context, id string) (*store.PendingRequest, error) {
	row := s.db.QueryRowContext(ctx, pendingSelect+` WHERE id = ?`, id)
	return scanPending(row)
}

func (s *Store) ListPending(ctx context.Context) ([]store.PendingRequest, error) {
	rows, err := s.db.QueryContext(ctx, pendingSelect+` ORDER BY first_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.PendingRequest, 0)
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) DeletePending(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending WHERE id = ?`, id)
	return err
}

func (s *Store) FindPendingByPublicKey(ctx context.Context, pubkey string) (*store.PendingRequest, error) {
	row := s.db.QueryRowContext(ctx, pendingSelect+` WHERE public_key = ? LIMIT 1`, pubkey)
	return scanPending(row)
}

const pendingSelect = `SELECT id, device_id, public_key, facts, fingerprint, reason, first_seen, last_seen FROM pending`

func scanPending(r rowScanner) (*store.PendingRequest, error) {
	var p store.PendingRequest
	var factsJSON sql.NullString
	var first, last int64
	if err := r.Scan(&p.ID, &p.DeviceID, &p.PublicKey, &factsJSON, &p.Fingerprint, &p.Reason, &first, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if factsJSON.Valid {
		var f protocol.DeviceFacts
		_ = json.Unmarshal([]byte(factsJSON.String), &f)
		p.Facts = f
	}
	p.FirstSeen = time.UnixMilli(first).UTC()
	p.LastSeen = time.UnixMilli(last).UTC()
	return &p, nil
}

// --- Allowlist ------------------------------------------------------------

func (s *Store) AddAllowlist(ctx context.Context, e store.AllowlistEntry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO allowlist (device_id, mac, serial, note, profile, created_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(device_id) DO UPDATE SET
			mac = excluded.mac, serial = excluded.serial, note = excluded.note, profile = excluded.profile`,
		e.DeviceID, nullStr(e.MAC), nullStr(e.Serial), nullStr(e.Note), nullStr(e.Profile), e.CreatedAt.UnixMilli())
	return err
}

func (s *Store) RemoveAllowlist(ctx context.Context, deviceID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM allowlist WHERE device_id = ?`, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ListAllowlist(ctx context.Context) ([]store.AllowlistEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, mac, serial, note, profile, created_at FROM allowlist ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.AllowlistEntry, 0)
	for rows.Next() {
		var e store.AllowlistEntry
		var mac, serial, note, profile sql.NullString
		var ts int64
		if err := rows.Scan(&e.DeviceID, &mac, &serial, &note, &profile, &ts); err != nil {
			return nil, err
		}
		e.MAC, e.Serial, e.Note, e.Profile = mac.String, serial.String, note.String, profile.String
		e.CreatedAt = time.UnixMilli(ts).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) LookupAllowlist(ctx context.Context, deviceID string) (*store.AllowlistEntry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT device_id, mac, serial, note, profile, created_at FROM allowlist WHERE device_id = ?`, deviceID)
	var e store.AllowlistEntry
	var mac, serial, note, profile sql.NullString
	var ts int64
	if err := row.Scan(&e.DeviceID, &mac, &serial, &note, &profile, &ts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	e.MAC, e.Serial, e.Note, e.Profile = mac.String, serial.String, note.String, profile.String
	e.CreatedAt = time.UnixMilli(ts).UTC()
	return &e, nil
}

// --- Tokens ---------------------------------------------------------------

func (s *Store) AddToken(ctx context.Context, t store.BootstrapToken) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	var exp sql.NullInt64
	if !t.ExpiresAt.IsZero() {
		exp = sql.NullInt64{Int64: t.ExpiresAt.UnixMilli(), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tokens (id, hash, device_id, expires_at, uses, max_uses, created_at, profile)
		VALUES (?,?,?,?,?,?,?,?)`,
		t.ID, t.Hash, nullStr(t.DeviceID), exp, t.Uses, t.MaxUses, t.CreatedAt.UnixMilli(), nullStr(t.Profile))
	return err
}

func (s *Store) GetTokenByHash(ctx context.Context, hash string) (*store.BootstrapToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, hash, device_id, expires_at, uses, max_uses, created_at, profile FROM tokens WHERE hash = ?`, hash)
	return scanToken(row)
}

func (s *Store) IncrementTokenUse(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE tokens SET uses = uses + 1 WHERE id = ?`, id)
	return err
}

func (s *Store) RevokeToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ListTokens(ctx context.Context) ([]store.BootstrapToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, hash, device_id, expires_at, uses, max_uses, created_at, profile FROM tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.BootstrapToken, 0)
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func scanToken(r rowScanner) (*store.BootstrapToken, error) {
	var t store.BootstrapToken
	var dev, profile sql.NullString
	var exp sql.NullInt64
	var created int64
	if err := r.Scan(&t.ID, &t.Hash, &dev, &exp, &t.Uses, &t.MaxUses, &created, &profile); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	t.DeviceID = dev.String
	t.Profile = profile.String
	if exp.Valid {
		t.ExpiresAt = time.UnixMilli(exp.Int64).UTC()
	}
	t.CreatedAt = time.UnixMilli(created).UTC()
	return &t, nil
}

// --- Nonces ---------------------------------------------------------------

func (s *Store) RememberNonce(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	now := time.Now().UTC()
	// Opportunistic GC of expired nonces.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM nonces WHERE expires_at < ?`, now.UnixMilli())

	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO nonces (nonce, expires_at) VALUES (?, ?)`,
		nonce, now.Add(ttl).UnixMilli())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) ForgetNonce(ctx context.Context, nonce string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM nonces WHERE nonce = ?`, nonce)
	return err
}

// --- Audit ----------------------------------------------------------------

func (s *Store) AppendAudit(ctx context.Context, e store.AuditEntry) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit (at, actor, action, device_id, details) VALUES (?,?,?,?,?)`,
		e.At.UnixMilli(), e.Actor, e.Action, nullStr(e.DeviceID), e.Details)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT at, actor, action, device_id, details FROM audit ORDER BY rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.AuditEntry, 0)
	for rows.Next() {
		var e store.AuditEntry
		var dev sql.NullString
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Action, &dev, &e.Details); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(at).UTC()
		e.DeviceID = dev.String
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
