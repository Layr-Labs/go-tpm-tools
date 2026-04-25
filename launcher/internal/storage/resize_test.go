package storage

import (
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
