package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
)

func TestCheckDevice(t *testing.T) {
	t.Parallel()

	t.Run("accepts allowlisted device", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, checkDevice(allowedBackingDevice))
	})

	t.Run("rejects other device", func(t *testing.T) {
		t.Parallel()
		err := checkDevice("/dev/sda")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Contains(t, err.Error(), "device=")
	})
}

func TestCheckMapper(t *testing.T) {
	t.Parallel()

	t.Run("accepts allowlisted mapper", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, checkMapper(allowedMapper))
	})

	t.Run("rejects other mapper", func(t *testing.T) {
		t.Parallel()
		err := checkMapper("/dev/mapper/protected_stateful_partition")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Contains(t, err.Error(), "mapper=")
	})
}

func TestCheckMount(t *testing.T) {
	t.Parallel()

	t.Run("accepts allowlisted mount", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, checkMount(allowedMountPoint))
	})

	t.Run("rejects other mount", func(t *testing.T) {
		t.Parallel()
		err := checkMount("/")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Contains(t, err.Error(), "mount=")
	})
}

func TestPdSizeBytes(t *testing.T) {
	t.Parallel()

	t.Run("parses blockdev output", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", []string{"--getsize64", allowedBackingDevice}, []byte("107374182400\n"), nil)

		n, err := pdSizeBytes(context.Background(), r, allowedBackingDevice)
		require.NoError(t, err)
		assert.Equal(t, uint64(107374182400), n)
	})

	t.Run("rejects non-allowlisted device", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		_, err := pdSizeBytes(context.Background(), r, "/dev/sda")
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Empty(t, r.Calls(), "must not exec when allowlist rejects")
	})

	t.Run("wraps blockdev error", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", nil, nil, errors.New("boom"))
		_, err := pdSizeBytes(context.Background(), r, allowedBackingDevice)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "boom")
	})
}

func TestMapperSizeBytes(t *testing.T) {
	t.Parallel()

	t.Run("parses blockdev output", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", []string{"--getsize64", allowedMapper}, []byte("214748364800\n"), nil)

		n, err := mapperSizeBytes(context.Background(), r, allowedMapper)
		require.NoError(t, err)
		assert.Equal(t, uint64(214748364800), n)
	})

	t.Run("rejects non-allowlisted mapper", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		_, err := mapperSizeBytes(context.Background(), r, "/dev/mapper/protected_stateful_partition")
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Empty(t, r.Calls())
	})
}

func TestKernelRescanPD(t *testing.T) {
	t.Parallel()

	t.Run("writes 1 to rescan sysfs node", func(t *testing.T) {
		t.Parallel()
		// Use a temp file as a stand-in for /sys/block/<dev>/device/rescan.
		tmp := t.TempDir() + "/rescan"
		require.NoError(t, os.WriteFile(tmp, []byte(""), 0o644))

		require.NoError(t, writeRescan(tmp))

		b, err := os.ReadFile(tmp)
		require.NoError(t, err)
		assert.Equal(t, "1", strings.TrimSpace(string(b)))
	})

	t.Run("rejects non-allowlisted device", func(t *testing.T) {
		t.Parallel()
		err := kernelRescanPD("/dev/sda")
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
	})
}

func TestLuksResize(t *testing.T) {
	t.Parallel()

	t.Run("invokes cryptsetup resize", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("cryptsetup", []string{"resize", "userdata"}, nil, nil)
		require.NoError(t, luksResize(context.Background(), r, "userdata"))
		calls := r.Calls()
		require.Len(t, calls, 1)
		assert.Equal(t, "cryptsetup", calls[0].name)
		assert.Equal(t, []string{"resize", "userdata"}, calls[0].args)
	})

	t.Run("rejects wrong mapper name", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		err := luksResize(context.Background(), r, "protected_stateful_partition")
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Empty(t, r.Calls())
	})

	t.Run("wraps cryptsetup error", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("cryptsetup", nil, nil, errors.New("device not active"))
		err := luksResize(context.Background(), r, "userdata")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device not active")
	})
}

func TestResizeExt4(t *testing.T) {
	t.Parallel()

	t.Run("invokes resize2fs on allowed mapper", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("resize2fs", []string{allowedMapper}, nil, nil)
		require.NoError(t, resizeExt4(context.Background(), r, allowedMapper))
		calls := r.Calls()
		require.Len(t, calls, 1)
		assert.Equal(t, "resize2fs", calls[0].name)
		assert.Equal(t, []string{allowedMapper}, calls[0].args)
	})

	t.Run("rejects non-allowlisted device", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		err := resizeExt4(context.Background(), r, "/dev/mapper/protected_stateful_partition")
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Empty(t, r.Calls())
	})
}

func TestVerifyMountedFromMapper(t *testing.T) {
	t.Parallel()

	t.Run("accepts matching findmnt output", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("findmnt", []string{"-n", "-o", "SOURCE", allowedMountPoint},
			[]byte(allowedMapper+"\n"), nil)
		require.NoError(t, verifyMountedFromMapper(context.Background(), r, allowedMountPoint, allowedMapper))
	})

	t.Run("rejects wrong source", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("findmnt", nil, []byte("/dev/sda1\n"), nil)
		err := verifyMountedFromMapper(context.Background(), r, allowedMountPoint, allowedMapper)
		assert.ErrorIs(t, err, ErrMountNotPresent)
	})

	t.Run("rejects when findmnt fails", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("findmnt", nil, nil, errors.New("not mounted"))
		err := verifyMountedFromMapper(context.Background(), r, allowedMountPoint, allowedMapper)
		assert.ErrorIs(t, err, ErrMountNotPresent)
	})

	t.Run("rejects non-allowlisted mount point", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		err := verifyMountedFromMapper(context.Background(), r, "/", allowedMapper)
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Empty(t, r.Calls())
	})

	t.Run("rejects non-allowlisted mapper", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		err := verifyMountedFromMapper(context.Background(), r, allowedMountPoint, "/dev/mapper/protected_stateful_partition")
		assert.ErrorIs(t, err, ErrDeviceNotAllowed)
		assert.Empty(t, r.Calls())
	})
}

// testLogger returns a no-op logging.Logger for tests that don't inspect output.
func testLogger(t *testing.T) logging.Logger {
	t.Helper()
	return discardLogger{}
}

func TestGrowOnce(t *testing.T) {
	t.Parallel()

	scriptSuccess := func(r *fakeRunner, pdBytes, mapperBytes uint64) {
		r.Expect("blockdev", []string{"--getsize64", allowedBackingDevice},
			[]byte(fmt.Sprintf("%d\n", pdBytes)), nil)
		r.Expect("blockdev", []string{"--getsize64", allowedMapper},
			[]byte(fmt.Sprintf("%d\n", mapperBytes)), nil)
		r.Expect("findmnt", []string{"-n", "-o", "SOURCE", allowedMountPoint},
			[]byte(allowedMapper+"\n"), nil)
		r.Expect("cryptsetup", []string{"resize", luksMapperName}, nil, nil)
		r.Expect("resize2fs", []string{allowedMapper}, nil, nil)
	}

	t.Run("noop when sizes equal", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", []string{"--getsize64", allowedBackingDevice}, []byte("100\n"), nil)
		r.Expect("blockdev", []string{"--getsize64", allowedMapper}, []byte("100\n"), nil)

		require.NoError(t, growOnce(context.Background(), r, testLogger(t)))
		assert.Len(t, r.Calls(), 2, "only the two size reads; no resize invoked")
	})

	t.Run("grows when pd larger", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		scriptSuccess(r, 200, 100)

		require.NoError(t, growOnce(context.Background(), r, testLogger(t)))
		calls := r.Calls()
		require.Len(t, calls, 5)
		assert.Equal(t, "blockdev", calls[0].name)
		assert.Equal(t, "blockdev", calls[1].name)
		assert.Equal(t, "findmnt", calls[2].name)
		assert.Equal(t, "cryptsetup", calls[3].name)
		assert.Equal(t, "resize2fs", calls[4].name)
	})

	t.Run("skips shrink", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", []string{"--getsize64", allowedBackingDevice}, []byte("50\n"), nil)
		r.Expect("blockdev", []string{"--getsize64", allowedMapper}, []byte("100\n"), nil)

		require.NoError(t, growOnce(context.Background(), r, testLogger(t)))
		assert.Len(t, r.Calls(), 2)
	})

	t.Run("mount-check failure aborts resize", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", []string{"--getsize64", allowedBackingDevice}, []byte("200\n"), nil)
		r.Expect("blockdev", []string{"--getsize64", allowedMapper}, []byte("100\n"), nil)
		r.Expect("findmnt", nil, []byte("/dev/sda1\n"), nil)

		err := growOnce(context.Background(), r, testLogger(t))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMountNotPresent)
		for _, c := range r.Calls() {
			assert.NotEqual(t, "cryptsetup", c.name)
			assert.NotEqual(t, "resize2fs", c.name)
		}
	})

	t.Run("cryptsetup error propagates", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", []string{"--getsize64", allowedBackingDevice}, []byte("200\n"), nil)
		r.Expect("blockdev", []string{"--getsize64", allowedMapper}, []byte("100\n"), nil)
		r.Expect("findmnt", nil, []byte(allowedMapper+"\n"), nil)
		r.Expect("cryptsetup", nil, nil, errors.New("boom"))

		err := growOnce(context.Background(), r, testLogger(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "boom")
	})

	t.Run("resize2fs error propagates", func(t *testing.T) {
		t.Parallel()
		r := newFakeRunner()
		r.Expect("blockdev", []string{"--getsize64", allowedBackingDevice}, []byte("200\n"), nil)
		r.Expect("blockdev", []string{"--getsize64", allowedMapper}, []byte("100\n"), nil)
		r.Expect("findmnt", nil, []byte(allowedMapper+"\n"), nil)
		r.Expect("cryptsetup", nil, nil, nil)
		r.Expect("resize2fs", nil, nil, errors.New("kaboom"))

		err := growOnce(context.Background(), r, testLogger(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kaboom")
	})
}
