// Package storage: online grow of the secondary LUKS-encrypted PD.
package storage

import (
	"errors"
	"fmt"
)

// Allowlist: the only device chain this package will ever touch.
// All primitives reject arguments that don't match these constants, so a
// refactor accidentally pointing at the boot disk fails before any
// subprocess is spawned.
const (
	allowedBackingDevice = "/dev/disk/by-id/google-persistent_storage_1"
	allowedMapper        = "/dev/mapper/userdata"
	allowedMountPoint    = "/mnt/disks/userdata"
)

// Sentinel errors. Callers use errors.Is to distinguish precondition failures
// from transient subprocess errors.
var (
	ErrDeviceNotAllowed = errors.New("storage: device outside allowlist")
	ErrMapperNotOpen    = errors.New("storage: LUKS mapper not present")
	ErrMountNotPresent  = errors.New("storage: expected mount point not found")
)

func checkAllowed(device, mapper, mountPoint string) error {
	if device != allowedBackingDevice {
		return fmt.Errorf("%w: device=%q", ErrDeviceNotAllowed, device)
	}
	if mapper != allowedMapper {
		return fmt.Errorf("%w: mapper=%q", ErrDeviceNotAllowed, mapper)
	}
	if mountPoint != allowedMountPoint {
		return fmt.Errorf("%w: mount=%q", ErrDeviceNotAllowed, mountPoint)
	}
	return nil
}
