package storage

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
