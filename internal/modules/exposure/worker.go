package exposure

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// Worker recomputes exposure scores for every org on a timer, so scores
// stay current as findings/attack paths/risk scores change without
// touching any of those engines.
type Worker struct {
	engine   *Engine
	log      *zap.SugaredLogger
	interval time.Duration

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewWorker constructs a Worker. A zero interval defaults to 5 minutes.
func NewWorker(engine *Engine, log *zap.SugaredLogger, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Worker{engine: engine, log: log, interval: interval}
}

// Start launches the periodic recompute loop in the background. Safe to
// call once; a second call is a no-op until Stop is called.
func (w *Worker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running {
		return
	}
	w.running = true
	w.stopCh = make(chan struct{})
	w.doneCh = make(chan struct{})

	go func() {
		defer close(w.doneCh)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		// Run once immediately so scores exist as soon as the app starts,
		// rather than waiting a full interval.
		w.runOnce()

		for {
			select {
			case <-ticker.C:
				w.runOnce()
			case <-w.stopCh:
				return
			}
		}
	}()

	w.log.Infow("exposure: background worker started", "interval", w.interval.String())
}

// Stop signals the worker loop to exit and blocks until it has.
func (w *Worker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	close(w.stopCh)
	w.mu.Unlock()

	<-w.doneCh
	w.log.Info("exposure: background worker stopped")
}

// RunNow triggers an immediate recompute across every org.
func (w *Worker) RunNow() (int, error) {
	return w.engine.RecomputeAllOrgs()
}

func (w *Worker) runOnce() {
	done, err := w.engine.RecomputeAllOrgs()
	if err != nil {
		w.log.Warnw("exposure: worker recompute pass failed", "error", err)
		return
	}
	w.log.Infow("exposure: worker recompute pass complete", "orgs", done)
}
