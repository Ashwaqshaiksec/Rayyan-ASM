package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/redis/go-redis/v9"
)

type Job struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Payload  map[string]interface{} `json:"payload"`
	Attempts int                    `json:"attempts"`
	MaxRetry int                    `json:"max_retry"`
	Priority int                    `json:"priority"`
}

type Handler func(ctx context.Context, job Job) error

// FailedJobSink receives jobs that have exhausted all retries.
// Callers inject a DB-backed sink; the zero value (nil) silently discards.
type FailedJobSink func(job Job, lastErr error)

type Queue struct {
	redis    *RedisClient
	cfg      config.QueueConfig
	inMemory chan Job
	handlers map[string]Handler
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	dlq      FailedJobSink
}

func New(redis *RedisClient, cfg config.QueueConfig) *Queue {
	ctx, cancel := context.WithCancel(context.Background())
	q := &Queue{
		redis:    redis,
		cfg:      cfg,
		inMemory: make(chan Job, cfg.BufferSize),
		handlers: make(map[string]Handler),
		ctx:      ctx,
		cancel:   cancel,
	}
	q.startWorkers()
	return q
}

// SetDLQ installs a dead-letter sink called when a job exhausts all retries.
func (q *Queue) SetDLQ(sink FailedJobSink) {
	q.mu.Lock()
	q.dlq = sink
	q.mu.Unlock()
}

func (q *Queue) Register(jobType string, handler Handler) {
	q.mu.Lock()
	q.handlers[jobType] = handler
	q.mu.Unlock()
}

func (q *Queue) Enqueue(job Job) {
	if job.MaxRetry == 0 {
		job.MaxRetry = 3
	}

	if q.redis != nil {
		data, err := json.Marshal(job)
		if err != nil {
			return
		}
		if err := q.redis.client.LPush(context.Background(), "rayyan:queue:jobs", data).Err(); err != nil {
			// Redis unavailable — fall through to in-memory if possible.
			q.enqueueInMemory(job)
		}
		return
	}

	q.enqueueInMemory(job)
}

func (q *Queue) enqueueInMemory(job Job) {
	select {
	case q.inMemory <- job:
	default:
		// Channel full — send to DLQ immediately with a descriptive error.
		q.mu.RLock()
		sink := q.dlq
		q.mu.RUnlock()
		if sink != nil {
			sink(job, fmt.Errorf("queue buffer full: job dropped without execution"))
		}
	}
}

func (q *Queue) startWorkers() {
	workers := q.cfg.Workers
	if workers <= 0 {
		workers = 5
	}
	for i := 0; i < workers; i++ {
		q.wg.Add(1)
		go q.worker(i)
	}
}

func (q *Queue) worker(id int) {
	defer q.wg.Done()

	for {
		select {
		case <-q.ctx.Done():
			return
		default:
		}

		var job Job
		var got bool

		if q.redis != nil {
			data, err := q.redis.client.BRPop(q.ctx, 1*time.Second, "rayyan:queue:jobs").Result()
			if err == nil && len(data) > 1 {
				json.Unmarshal([]byte(data[1]), &job) //nolint:errcheck
				got = true
			}
		} else {
			select {
			case j := <-q.inMemory:
				job = j
				got = true
			case <-q.ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}

		if !got {
			continue
		}

		q.mu.RLock()
		handler, ok := q.handlers[job.Type]
		dlq := q.dlq
		q.mu.RUnlock()

		if !ok {
			if dlq != nil {
				dlq(job, fmt.Errorf("no handler registered for job type %q", job.Type))
			}
			continue
		}

		var lastErr error
		for attempt := 0; attempt <= job.MaxRetry; attempt++ {
			job.Attempts = attempt + 1
			ctx, cancel := context.WithTimeout(q.ctx, 30*time.Minute)

			func() {
				defer func() {
					if r := recover(); r != nil {
						lastErr = fmt.Errorf("job handler panicked: %v", r)
					}
				}()
				lastErr = handler(ctx, job)
			}()
			cancel()

			if lastErr == nil {
				break
			}

			if attempt < job.MaxRetry {
				backoff := time.Duration(attempt+1) * 5 * time.Second
				select {
				case <-time.After(backoff):
				case <-q.ctx.Done():
					return
				}
			}
		}

		if lastErr != nil && dlq != nil {
			dlq(job, lastErr)
		}
	}
}

func (q *Queue) Stop() {
	q.cancel()
	q.wg.Wait()
}

// RedisClient wraps go-redis and satisfies the TokenRevoker interface used by
// the auth middleware so the two packages don't import each other.
type RedisClient struct {
	client *redis.Client
}

func NewRedisClient(cfg config.RedisConfig) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address(),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("connecting to Redis: %w", err)
	}

	return &RedisClient{client: client}, nil
}

func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *RedisClient) Del(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}
