package storage

import (
	"context"
	"io/fs"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeStat returns a stat function that reports the device as missing for
// the first `appearAfter` calls and present after that. Threadsafe: tests
// drive the ticker channel directly so multiple goroutines aren't needed,
// but using atomic.Int32 keeps the helper safe regardless.
func fakeStat(appearAfter int32) (statFunc, *atomic.Int32) {
	var calls atomic.Int32
	return func(string) (os.FileInfo, error) {
		n := calls.Add(1)
		if n > appearAfter {
			// Device "appears" — return a non-nil FileInfo. The
			// findSecondaryDevice contract only checks err == nil, so a
			// dummy stat suffices and we don't have to construct a real
			// fs.FileInfo.
			return fakeFileInfo{}, nil
		}
		return nil, &fs.PathError{Op: "stat", Path: secondaryDevicePath, Err: fs.ErrNotExist}
	}, &calls
}

// fakeFileInfo satisfies os.FileInfo with no-op fields. Only the
// non-nil-error contract of stat matters to findSecondaryDevice.
type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return secondaryDevicePath }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }

// tickerHarness produces a tickerFunc whose underlying channel is
// owned by the test, so the poll loop's cadence is fully driven by
// writes to harness.tick.
type tickerHarness struct {
	tick     chan time.Time
	tickerOf func(time.Duration) *time.Ticker
}

// newTickerHarness builds a fakeable ticker for findSecondaryDeviceWith.
// time.Ticker has no exported constructor that lets the caller own .C,
// but assigning to the public field after time.NewTicker leaves Stop()
// safely callable on the underlying internal state. We construct a
// long-interval real ticker (so its real channel never fires) and
// replace its .C with our own.
func newTickerHarness() *tickerHarness {
	h := &tickerHarness{tick: make(chan time.Time, 1)}
	h.tickerOf = func(time.Duration) *time.Ticker {
		realTicker := time.NewTicker(time.Hour)
		realTicker.C = h.tick
		return realTicker
	}
	return h
}

func TestFindSecondaryDevice_FastPath_DeviceAlreadyPresent(t *testing.T) {
	t.Parallel()
	stat, calls := fakeStat(0) // present immediately

	got := findSecondaryDeviceWith(
		context.Background(),
		testLogger(t),
		stat,
		time.NewTicker, // not exercised on the fast path
		30*time.Second,
	)

	assert.Equal(t, secondaryDevicePath, got)
	assert.EqualValues(t, 1, calls.Load(), "only the fast-path stat should run when device is already present")
}

func TestFindSecondaryDevice_DeviceAppearsDuringPoll(t *testing.T) {
	t.Parallel()
	// Miss the fast path twice (the initial pre-loop check counts as
	// call #1 and the first ticker poll counts as call #2), then appear.
	stat, calls := fakeStat(2)
	harness := newTickerHarness()

	done := make(chan string, 1)
	go func() {
		done <- findSecondaryDeviceWith(
			context.Background(),
			testLogger(t),
			stat,
			harness.tickerOf,
			30*time.Second,
		)
	}()

	// Drive two ticks. The third stat (after tick #2) sees the device.
	harness.tick <- time.Now()
	harness.tick <- time.Now()

	select {
	case got := <-done:
		assert.Equal(t, secondaryDevicePath, got)
	case <-time.After(2 * time.Second):
		t.Fatal("findSecondaryDeviceWith did not return after device appeared")
	}
	assert.GreaterOrEqual(t, calls.Load(), int32(3),
		"expected at least the initial stat plus two polled stats")
}

func TestFindSecondaryDevice_TimeoutFallsBackToBootDisk(t *testing.T) {
	t.Parallel()
	// Device never appears.
	stat := func(string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: secondaryDevicePath, Err: fs.ErrNotExist}
	}

	// Tight timeout — using a real (short) ticker is fine here since
	// the timeout is what we're exercising and we want it to fire fast.
	got := findSecondaryDeviceWith(
		context.Background(),
		testLogger(t),
		stat,
		time.NewTicker,
		25*time.Millisecond,
	)

	assert.Equal(t, "", got, "must return empty (boot-disk fallback) on timeout")
}

func TestFindSecondaryDevice_ContextCancelExitsLoop(t *testing.T) {
	t.Parallel()
	stat := func(string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: secondaryDevicePath, Err: fs.ErrNotExist}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() {
		// Long timeout so the only exit signal can be the cancel.
		done <- findSecondaryDeviceWith(ctx, testLogger(t), stat, time.NewTicker, 10*time.Second)
	}()

	// Give the goroutine a moment to enter the select, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case got := <-done:
		assert.Equal(t, "", got, "context cancel must fall back to boot disk, not panic or block")
	case <-time.After(2 * time.Second):
		t.Fatal("findSecondaryDeviceWith did not return after context cancel")
	}
}

func TestFindSecondaryDevice_ParentContextDeadlinePropagates(t *testing.T) {
	t.Parallel()
	// Regression guard: the inner timeout context is derived from the
	// parent. If the parent's deadline is shorter, it must take effect —
	// a long inner timeout should not extend the outer caller's window.
	stat := func(string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: secondaryDevicePath, Err: fs.ErrNotExist}
	}

	parent, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	got := findSecondaryDeviceWith(parent, testLogger(t), stat, time.NewTicker, 10*time.Second)
	elapsed := time.Since(start)

	assert.Equal(t, "", got)
	assert.Less(t, elapsed, 500*time.Millisecond,
		"parent context's 30ms deadline must short-circuit the 10s probe timeout")
}

// secondaryDeviceProbeTimeoutIsSane is a guardrail against accidental
// changes to the production constants. Reviewers should treat a failure
// here as a prompt to update the spec doc + this test together.
func TestSecondaryDeviceProbeConstantsAreSane(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 30*time.Second, secondaryDeviceProbeTimeout)
	assert.Equal(t, 500*time.Millisecond, secondaryDeviceProbeInterval)
	assert.Less(t, secondaryDeviceProbeInterval, secondaryDeviceProbeTimeout,
		"interval must be smaller than timeout or polling never fires")
}

// TestLateAttachDeviceTimeoutIsSane locks in the contract that the
// late-attach budget exceeds the synchronous-path budget. The
// orchestrator's prewarm-detach round trip + GCE attach can take
// several minutes and must fit inside this window; if anyone ever
// shortens it below the synchronous timeout, the asymmetry that
// motivates the separate path collapses.
func TestLateAttachDeviceTimeoutIsSane(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 5*time.Minute, LateAttachDeviceTimeout)
	assert.Greater(t, LateAttachDeviceTimeout, secondaryDeviceProbeTimeout,
		"late-attach budget must exceed the synchronous-path budget")
}
