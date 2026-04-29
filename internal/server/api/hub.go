package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

// Hub fans out PendingRequest events to connected operators. Implemented as
// Server-Sent Events to keep the dependency footprint small (no WS lib) and
// to play nicely with HTTP/2 + ALBs in cloud deployments.
type Hub struct {
	mu      sync.Mutex
	clients map[chan *store.PendingRequest]struct{}
	// done is closed by Shutdown. Open SSE streams select on it and
	// return immediately, so http.Server.Shutdown doesn't block waiting
	// for the long-lived /v1/admin/pending/stream connections to drain.
	done chan struct{}
}

func NewHub() *Hub {
	return &Hub{
		clients: map[chan *store.PendingRequest]struct{}{},
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

// Notify is the function passed to EngineConfig.OnPending.
func (h *Hub) Notify(p *store.PendingRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- p:
		default:
			// Drop on slow consumers; they'll get the next event.
		}
	}
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

	ch := make(chan *store.PendingRequest, 8)
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
		case p := <-ch:
			b, err := json.Marshal(p)
			if err != nil {
				continue
			}
			_, _ = w.Write([]byte("event: pending\ndata: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}
