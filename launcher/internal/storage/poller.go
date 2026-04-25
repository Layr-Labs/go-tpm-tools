package storage

import (
	"context"
	"fmt"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
)

// DefaultPollInterval is the default cadence for the Poller.
const DefaultPollInterval = 60 * time.Second

// sizeSnapshot captures the three sizes we log each tick, plus FS availability.
type sizeSnapshot struct {
	PDSize     uint64
	MapperSize uint64
	FSSize     uint64
	FSAvail    uint64
}

// Poller periodically triggers a runtime grow and emits a structured size log.
// Construct via NewPoller; fields are test-visible within the package.
//
// Concurrency: Run runs in a single goroutine; there is no shared state
// between ticks that the caller needs to protect. Each tick recovers from
// panics so one bad call doesn't kill the loop.
type Poller struct {
	interval time.Duration
	logger   logging.Logger

	// Injection points for tests. Production code uses the defaults set
	// by NewPoller (GrowOnce + statfs-based sizeSnapshot).
	growFn     func(ctx context.Context) error
	snapshotFn func(ctx context.Context) (sizeSnapshot, error)
}

// NewPoller returns a production-configured Poller. interval <= 0 means
// DefaultPollInterval.
func NewPoller(logger logging.Logger, interval time.Duration) *Poller {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	return &Poller{
		interval:   interval,
		logger:     logger,
		growFn:     func(ctx context.Context) error { return GrowOnce(ctx, logger) },
		snapshotFn: defaultSizeSnapshot,
	}
}

// Run blocks until ctx is canceled, returning ctx.Err() on exit.
func (p *Poller) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.logger.Info("disk-grow poller started", "interval", p.interval.String())
	defer p.logger.Info("disk-grow poller stopped")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			p.tick(ctx)
		}
	}
}

// tick wraps a single poll iteration with panic recovery so a single bad
// call can't silently kill the loop.
func (p *Poller) tick(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("poller tick panicked; recovered",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()),
			)
		}
	}()

	if err := p.growFn(ctx); err != nil {
		p.logger.Warn("grow tick failed", "error", err)
	}

	snap, err := p.snapshotFn(ctx)
	if err != nil {
		p.logger.Warn("size snapshot failed", "error", err)
		return
	}
	p.logger.Info("disk sizes",
		"pd_size_bytes", snap.PDSize,
		"mapper_size_bytes", snap.MapperSize,
		"fs_size_bytes", snap.FSSize,
		"fs_available_bytes", snap.FSAvail,
	)
}

// defaultSizeSnapshot reads production sizes from blockdev + statfs.
func defaultSizeSnapshot(ctx context.Context) (sizeSnapshot, error) {
	pd, err := pdSizeBytes(ctx, defaultRunner, allowedBackingDevice)
	if err != nil {
		return sizeSnapshot{}, err
	}
	mapper, err := mapperSizeBytes(ctx, defaultRunner, allowedMapper)
	if err != nil {
		return sizeSnapshot{}, err
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(allowedMountPoint, &st); err != nil {
		return sizeSnapshot{}, fmt.Errorf("statfs %s: %w", allowedMountPoint, err)
	}
	return sizeSnapshot{
		PDSize:     pd,
		MapperSize: mapper,
		FSSize:     uint64(st.Blocks) * uint64(st.Bsize),
		FSAvail:    uint64(st.Bavail) * uint64(st.Bsize),
	}, nil
}
