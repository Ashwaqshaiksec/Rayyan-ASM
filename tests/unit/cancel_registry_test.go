package unit_test

import (
	"context"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCancelRegistry(t *testing.T) {
	reg := modules.NewCancelRegistryForTest()
	jobID := uuid.New()
	ctx, cancel := context.WithCancel(context.Background())

	reg.Register(jobID, cancel)

	// Should signal the goroutine
	cancelled := reg.Cancel(jobID)
	assert.True(t, cancelled)

	// Context should now be cancelled
	select {
	case <-ctx.Done():
		// Good
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context was not cancelled within timeout")
	}

	// Second cancel should return false (already consumed)
	cancelled2 := reg.Cancel(jobID)
	assert.False(t, cancelled2)
}

func TestCancelRegistryDeregister(t *testing.T) {
	reg := modules.NewCancelRegistryForTest()
	jobID := uuid.New()
	_, cancel := context.WithCancel(context.Background())

	reg.Register(jobID, cancel)
	reg.Deregister(jobID)

	// After deregister, Cancel should return false
	assert.False(t, reg.Cancel(jobID))
}
