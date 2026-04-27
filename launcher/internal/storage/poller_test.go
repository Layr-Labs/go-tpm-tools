package storage

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestPollerTicksAndCallsGrow(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	p := &Poller{
		interval: 10 * time.Millisecond,
		logger:   testLogger(t),
		growFn: func(ctx context.Context) error {
			calls.Add(1)
			return nil
		},
		snapshotFn: func(ctx context.Context) (sizeSnapshot, error) {
			return sizeSnapshot{}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, p.Run(ctx), context.DeadlineExceeded)
	assert.GreaterOrEqual(t, calls.Load(), int32(1))
}

func TestPollerContinuesAfterError(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	p := &Poller{
		interval: 5 * time.Millisecond,
		logger:   testLogger(t),
		growFn: func(ctx context.Context) error {
			calls.Add(1)
			return errors.New("boom")
		},
		snapshotFn: func(ctx context.Context) (sizeSnapshot, error) {
			return sizeSnapshot{}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, p.Run(ctx), context.DeadlineExceeded)
	assert.GreaterOrEqual(t, calls.Load(), int32(2), "must keep ticking after errors")
}

func TestPollerStopsOnContextCancel(t *testing.T) {
	t.Parallel()

	p := &Poller{
		interval: 10 * time.Millisecond,
		logger:   testLogger(t),
		growFn: func(ctx context.Context) error { return nil },
		snapshotFn: func(ctx context.Context) (sizeSnapshot, error) {
			return sizeSnapshot{}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("poller did not stop after cancel")
	}
}

func TestPollerRecoversFromPanic(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	p := &Poller{
		interval: 5 * time.Millisecond,
		logger:   testLogger(t),
		growFn: func(ctx context.Context) error {
			n := calls.Add(1)
			if n == 1 {
				panic("kaboom")
			}
			return nil
		},
		snapshotFn: func(ctx context.Context) (sizeSnapshot, error) {
			return sizeSnapshot{}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, p.Run(ctx), context.DeadlineExceeded)
	assert.GreaterOrEqual(t, calls.Load(), int32(2), "must tick again after panic")
}

func TestPollerLogsSizesEachTick(t *testing.T) {
	t.Parallel()

	logger := &capturingLogger{}
	p := &Poller{
		interval: 10 * time.Millisecond,
		logger:   logger,
		growFn: func(ctx context.Context) error { return nil },
		snapshotFn: func(ctx context.Context) (sizeSnapshot, error) {
			return sizeSnapshot{PDSize: 100, MapperSize: 100, FSSize: 100, FSAvail: 80}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	msgs := logger.Infos()
	require.NotEmpty(t, msgs)
	found := false
	for _, m := range msgs {
		if containsAllKeys(m.args, "pd_size_bytes", "mapper_size_bytes", "fs_size_bytes", "fs_available_bytes") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected at least one size log line with all four keys; got %+v", msgs)
}

func containsAllKeys(kv []any, keys ...string) bool {
	have := map[string]bool{}
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			have[k] = true
		}
	}
	for _, k := range keys {
		if !have[k] {
			return false
		}
	}
	return true
}
