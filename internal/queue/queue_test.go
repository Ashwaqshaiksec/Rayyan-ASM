package queue_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/stretchr/testify/assert"
)

func newQueue(workers int) *queue.Queue {
	return queue.New(nil, config.QueueConfig{
		Workers:    workers,
		BufferSize: 100,
	})
}

func TestEnqueueAndProcess(t *testing.T) {
	q := newQueue(3)
	defer q.Stop()

	var processed int64
	q.Register("test", func(ctx context.Context, job queue.Job) error {
		atomic.AddInt64(&processed, 1)
		return nil
	})

	for i := 0; i < 10; i++ {
		q.Enqueue(queue.Job{ID: string(rune('a' + i)), Type: "test"})
	}

	// Wait for processing
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int64(10), atomic.LoadInt64(&processed))
}

func TestWorkerPoolConcurrency(t *testing.T) {
	q := newQueue(5)
	defer q.Stop()

	var mu sync.Mutex
	var maxConcurrent, current int
	var wg sync.WaitGroup

	q.Register("slow", func(ctx context.Context, job queue.Job) error {
		mu.Lock()
		current++
		if current > maxConcurrent {
			maxConcurrent = current
		}
		mu.Unlock()

		time.Sleep(50 * time.Millisecond)

		mu.Lock()
		current--
		mu.Unlock()
		wg.Done()
		return nil
	})

	total := 10
	wg.Add(total)
	for i := 0; i < total; i++ {
		q.Enqueue(queue.Job{ID: string(rune('A' + i)), Type: "slow"})
	}

	wg.Wait()
	assert.Greater(t, maxConcurrent, 1, "should process concurrently")
	assert.LessOrEqual(t, maxConcurrent, 5, "should not exceed worker count")
}

func TestUnregisteredJobType(t *testing.T) {
	q := newQueue(2)
	defer q.Stop()

	// Should not panic on unknown job type
	q.Enqueue(queue.Job{ID: "1", Type: "unknown_type"})
	time.Sleep(100 * time.Millisecond)
}

func TestQueueStop(t *testing.T) {
	q := newQueue(2)

	var processed int64
	q.Register("test", func(ctx context.Context, job queue.Job) error {
		atomic.AddInt64(&processed, 1)
		return nil
	})

	q.Enqueue(queue.Job{ID: "1", Type: "test"})
	time.Sleep(100 * time.Millisecond)

	// Stop should not hang
	done := make(chan struct{})
	go func() { q.Stop(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("queue.Stop() timed out")
	}
}
