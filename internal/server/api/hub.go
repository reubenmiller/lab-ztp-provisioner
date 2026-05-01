package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

// sseEvent is a typed Server-Sent Event that can carry any JSON payload.
type sseEvent struct {
	name string
	data []byte
}

// Hub fans out enrollment events to connected operators. Implemented as
// Server-Sent Events to keep the dependency footprint small (no WS lib) and
// to play nicely with HTTP/2 + ALBs in cloud deployments.
//
// Two event types are broadcast over the same stream:
//   - "pending"  — a device queued for manual approval (store.PendingRequest)
//   - "enrolled" — a device that auto-enrolled (store.Device)
type Hub struct {
	mu      sync.Mutex
	clients map[chan sseEvent]struct{}
	// done is closed by Shutdown. Open SSE streams select on it and
	// return immediately, so http.Server.Shutdown doesn't block waiting
	// for the long-lived /v1/admin/pending/stream connections to drain.
	done chan struct{}
}

func NewHub() *Hub {
	return &Hub{
		clients: map[chan sseEvent]struct{}{},
		done:    make(chan struct{}),
	}
}

// Shutdown signals every active SSE handler to return. Idempotent.
// Call before http.Server.Shutdown so its connection-drain phase
// completes immediately instead of waiting for SSE streams that
// would otherwise stay open until the per-request context is cancelled.
func (h *Hub) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.done:
		// already closed
	default:
		close(h.done)
	}
}

func (h *Hub) broadcast(ev sseEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- ev:
		default:
			// Drop on slow consumers; they'll get the next event.
		}
	}
}

// Notify is the function passed to EngineConfig.OnPending.
func (h *Hub) Notify(p *store.PendingRequest) {
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	h.broadcast(sseEvent{name: "pending", data: b})
}

// NotifyEnrolled is the function passed to EngineConfig.OnEnrolled.
func (h *Hub) NotifyEnrolled(d *store.Device) {
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	h.broadcast(sseEvent{name: "enrolled", data: b})
}

// ServeWS implements GET /v1/admin/pending/stream as an SSE stream despite
// the name; the route name is preserved to match the original plan but the
// transport is plain SSE which works without a websocket library.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan sseEvent, 8)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}()

	// Initial comment so clients see the connection is alive.
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-h.done:
			// Engine is shutting down — bail out so http.Server.Shutdown
			// doesn't block its connection drain on this stream.
			return
		case ev := <-ch:
			_, _ = w.Write([]byte("event: " + ev.name + "\ndata: "))
			_, _ = w.Write(ev.data)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}
