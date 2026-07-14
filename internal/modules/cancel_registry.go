package modules

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// CancelRegistry holds cancel functions for in-flight scan jobs so
// DELETE /scans/:id actually stops the running goroutine.
type CancelRegistry struct {
	mu      sync.Mutex
	cancels map[uuid.UUID]context.CancelFunc
}

// GlobalCancelRegistry is the process-wide registry used by handlers and dispatcher.
var GlobalCancelRegistry = newCancelRegistry()

func newCancelRegistry() *CancelRegistry {
	return &CancelRegistry{
		cancels: make(map[uuid.UUID]context.CancelFunc),
	}
}

// Register stores a cancel func for a scan job.
func (r *CancelRegistry) Register(jobID uuid.UUID, cancel context.CancelFunc) {
	r.mu.Lock()
	r.cancels[jobID] = cancel
	r.mu.Unlock()
}

// Cancel cancels a running scan job. Returns true if a job was found and cancelled.
func (r *CancelRegistry) Cancel(jobID uuid.UUID) bool {
	r.mu.Lock()
	cancel, ok := r.cancels[jobID]
	if ok {
		delete(r.cancels, jobID)
	}
	r.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// Deregister removes a job from the registry (called on completion).
func (r *CancelRegistry) Deregister(jobID uuid.UUID) {
	r.mu.Lock()
	delete(r.cancels, jobID)
	r.mu.Unlock()
}

// NewCancelRegistryForTest creates an isolated CancelRegistry for unit tests.
func NewCancelRegistryForTest() *CancelRegistry {
	return &CancelRegistry{
		cancels: make(map[uuid.UUID]context.CancelFunc),
	}
}
