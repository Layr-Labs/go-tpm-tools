package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAllowed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		device     string
		mapper     string
		mountPoint string
		wantErr    error
	}{
		{
			name:       "all match",
			device:     allowedBackingDevice,
			mapper:     allowedMapper,
			mountPoint: allowedMountPoint,
			wantErr:    nil,
		},
		{
			name:       "wrong device",
			device:     "/dev/sda",
			mapper:     allowedMapper,
			mountPoint: allowedMountPoint,
			wantErr:    ErrDeviceNotAllowed,
		},
		{
			name:       "wrong mapper",
			device:     allowedBackingDevice,
			mapper:     "/dev/mapper/protected_stateful_partition",
			mountPoint: allowedMountPoint,
			wantErr:    ErrDeviceNotAllowed,
		},
		{
			name:       "wrong mount",
			device:     allowedBackingDevice,
			mapper:     allowedMapper,
			mountPoint: "/",
			wantErr:    ErrDeviceNotAllowed,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkAllowed(tc.device, tc.mapper, tc.mountPoint)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
