// Package store defines persistence interfaces for the ZTP server.
//
// The default implementation in this package is an in-memory store suitable
// for tests and local single-instance deployments. Production deployments
// should implement Store against a durable backend (SQLite, Postgres, etc.).
// Keeping the surface narrow makes it easy to swap.
package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("not found")

// Decision is the outcome of running the verifier chain for a device.
type Decision string

const (
	DecisionTrust   Decision = "trust"
	DecisionPending Decision = "pending"
	DecisionReject  Decision = "reject"
)

// Device is a known, fully-enrolled device.
type Device struct {
	ID         string               `json:"id"`
	PublicKey  string               `json:"public_key"` // base64 Ed25519 (the device's identity key)
	Facts      protocol.DeviceFacts `json:"facts"`
	EnrolledAt time.Time            `json:"enrolled_at"`
	LastSeen   time.Time            `json:"last_seen"`
	// ProfileName is the provisioning profile resolved at the device's last
	// enrollment. Sticky: once set, future enrollments use it unless an
	// operator clears it (admin API) or sets Overrides["profile"].
	ProfileName string         `json:"profile_name,omitempty"`
	Overrides   map[string]any `json:"overrides,omitempty"` // per-device payload overrides (provider-specific)
}

// PendingRequest is a device awaiting manual approval.
type PendingRequest struct {
	ID          string               `json:"id"` // server-generated id (also used as approval token)
	DeviceID    string               `json:"device_id"`
	PublicKey   string               `json:"public_key"`
	Facts       protocol.DeviceFacts `json:"facts"`
	FirstSeen   time.Time            `json:"first_seen"`
	LastSeen    time.Time            `json:"last_seen"`
	Fingerprint string               `json:"fingerprint"`      // short human-readable fingerprint of PublicKey
	Reason      string               `json:"reason,omitempty"` // why it ended up pending (e.g. "no verifier matched")
}

// AllowlistEntry is a pre-registered identity that should be auto-trusted.
type AllowlistEntry struct {
	DeviceID  string    `json:"device_id"`
	MAC       string    `json:"mac,omitempty"`
	Serial    string    `json:"serial,omitempty"`
	Note      string    `json:"note,omitempty"`
	Profile   string    `json:"profile,omitempty"` // optional: profile to assign on auto-trust
	CreatedAt time.Time `json:"created_at"`
}

// BootstrapToken is a (single-use or time-bounded) credential a device can
// present to prove it was provisioned by an operator.
type BootstrapToken struct {
	ID        string    `json:"id"`
	Hash      string    `json:"-"`                   // SHA-256 hex of the token secret; never serialised
	DeviceID  string    `json:"device_id,omitempty"` // optional binding
	Profile   string    `json:"profile,omitempty"`   // optional: profile to assign on auto-trust
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Uses      int       `json:"uses"`
	MaxUses   int       `json:"max_uses"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry records a server-side decision or admin action for forensics.
type AuditEntry struct {
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`  // "system", "operator:<name>", "device:<id>"
	Action   string    `json:"action"` // e.g. "enroll.accept", "enroll.pending", "approve"
	DeviceID string    `json:"device_id,omitempty"`
	Details  string    `json:"details,omitempty"`
}

// Store is the persistence interface used by the server.
//
// All methods take context so implementations can support cancellation and
// distributed backends.
type Store interface {
	// Devices
	GetDevice(ctx context.Context, id string) (*Device, error)
	UpsertDevice(ctx context.Context, d *Device) error
	DeleteDevice(ctx context.Context, id string) error
	ListDevices(ctx context.Context) ([]Device, error)
	FindDeviceByPublicKey(ctx context.Context, pubkey string) (*Device, error)

	// Pending
	CreatePending(ctx context.Context, p *PendingRequest) error
	GetPending(ctx context.Context, id string) (*PendingRequest, error)
	ListPending(ctx context.Context) ([]PendingRequest, error)
	DeletePending(ctx context.Context, id string) error
	FindPendingByPublicKey(ctx context.Context, pubkey string) (*PendingRequest, error)

	// Allowlist
	AddAllowlist(ctx context.Context, e AllowlistEntry) error
	RemoveAllowlist(ctx context.Context, deviceID string) error
	ListAllowlist(ctx context.Context) ([]AllowlistEntry, error)
	LookupAllowlist(ctx context.Context, deviceID string) (*AllowlistEntry, error)

	// Tokens
	AddToken(ctx context.Context, t BootstrapToken) error
	GetTokenByHash(ctx context.Context, hash string) (*BootstrapToken, error)
	IncrementTokenUse(ctx context.Context, id string) error
	RevokeToken(ctx context.Context, id string) error
	ListTokens(ctx context.Context) ([]BootstrapToken, error)

	// Nonces (replay protection). Returns true if the nonce was newly stored.
	RememberNonce(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
	// ForgetNonce removes a nonce so the relay can re-submit the same signed
	// envelope after a pending → accepted transition without hitting "nonce replay".
	ForgetNonce(ctx context.Context, nonce string) error

	// Audit
	AppendAudit(ctx context.Context, e AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)
}

// Memory is an in-memory Store. Safe for concurrent use.
type Memory struct {
	mu         sync.RWMutex
	devices    map[string]Device
	pending    map[string]PendingRequest
	allow      map[string]AllowlistEntry
	tokens     map[string]BootstrapToken // keyed by hash
	tokensByID map[string]string         // id -> hash
	nonces     map[string]time.Time
	audit      []AuditEntry
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		devices:    map[string]Device{},
		pending:    map[string]PendingRequest{},
		allow:      map[string]AllowlistEntry{},
		tokens:     map[string]BootstrapToken{},
		tokensByID: map[string]string{},
		nonces:     map[string]time.Time{},
	}
}

func (m *Memory) GetDevice(_ context.Context, id string) (*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.devices[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &d, nil
}

func (m *Memory) UpsertDevice(_ context.Context, d *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[d.ID] = *d
	return nil
}

func (m *Memory) DeleteDevice(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.devices, id)
	return nil
}

func (m *Memory) ListDevices(_ context.Context) ([]Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Device, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, d)
	}
	return out, nil
}

func (m *Memory) FindDeviceByPublicKey(_ context.Context, pubkey string) (*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, d := range m.devices {
		if d.PublicKey == pubkey {
			return &d, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) CreatePending(_ context.Context, p *PendingRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending[p.ID] = *p
	return nil
}

func (m *Memory) GetPending(_ context.Context, id string) (*PendingRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pending[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &p, nil
}

func (m *Memory) ListPending(_ context.Context) ([]PendingRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PendingRequest, 0, len(m.pending))
	for _, p := range m.pending {
		out = append(out, p)
	}
	return out, nil
}

func (m *Memory) DeletePending(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, id)
	return nil
}

func (m *Memory) FindPendingByPublicKey(_ context.Context, pubkey string) (*PendingRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.pending {
		if p.PublicKey == pubkey {
			return &p, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) AddAllowlist(_ context.Context, e AllowlistEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	m.allow[e.DeviceID] = e
	return nil
}

func (m *Memory) RemoveAllowlist(_ context.Context, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.allow, deviceID)
	return nil
}

func (m *Memory) ListAllowlist(_ context.Context) ([]AllowlistEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]AllowlistEntry, 0, len(m.allow))
	for _, e := range m.allow {
		out = append(out, e)
	}
	return out, nil
}

func (m *Memory) LookupAllowlist(_ context.Context, deviceID string) (*AllowlistEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.allow[deviceID]
	if !ok {
		return nil, ErrNotFound
	}
	return &e, nil
}

func (m *Memory) AddToken(_ context.Context, t BootstrapToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.Hash] = t
	m.tokensByID[t.ID] = t.Hash
	return nil
}

func (m *Memory) GetTokenByHash(_ context.Context, hash string) (*BootstrapToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tokens[hash]
	if !ok {
		return nil, ErrNotFound
	}
	return &t, nil
}

func (m *Memory) IncrementTokenUse(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hash, ok := m.tokensByID[id]
	if !ok {
		return ErrNotFound
	}
	t := m.tokens[hash]
	t.Uses++
	m.tokens[hash] = t
	return nil
}

func (m *Memory) RevokeToken(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hash, ok := m.tokensByID[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.tokens, hash)
	delete(m.tokensByID, id)
	return nil
}

func (m *Memory) ListTokens(_ context.Context) ([]BootstrapToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]BootstrapToken, 0, len(m.tokens))
	for _, t := range m.tokens {
		// Never return the hash to the API layer's callers — but at the
		// store level we surface what we have; redaction is the caller's job.
		out = append(out, t)
	}
	return out, nil
}

func (m *Memory) RememberNonce(_ context.Context, nonce string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// Opportunistic GC.
	for k, exp := range m.nonces {
		if now.After(exp) {
			delete(m.nonces, k)
		}
	}
	if exp, ok := m.nonces[nonce]; ok && now.Before(exp) {
		return false, nil
	}
	m.nonces[nonce] = now.Add(ttl)
	return true, nil
}

func (m *Memory) ForgetNonce(_ context.Context, nonce string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nonces, nonce)
	return nil
}

func (m *Memory) AppendAudit(_ context.Context, e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	m.audit = append(m.audit, e)
	return nil
}

func (m *Memory) ListAudit(_ context.Context, limit int) ([]AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.audit) {
		limit = len(m.audit)
	}
	out := make([]AuditEntry, limit)
	copy(out, m.audit[len(m.audit)-limit:])
	return out, nil
}
