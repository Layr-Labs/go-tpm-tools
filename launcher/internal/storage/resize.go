// Package storage: online grow of the secondary LUKS-encrypted PD.
package storage

import (
	"errors"
	"fmt"
)

// Allowlist aliases — single source of truth lives in encrypted_volume.go.
// Using the same values ensures the guard cannot drift from the paths the
// rest of the package actually operates on.
const (
	allowedBackingDevice = secondaryDevicePath
	allowedMapper        = mapperPath
	allowedMountPoint    = MountPoint
)

// Sentinel errors. Callers use errors.Is to distinguish precondition failures
// from transient subprocess errors.
var (
	ErrDeviceNotAllowed = errors.New("storage: device outside allowlist")
	ErrMapperNotOpen    = errors.New("storage: LUKS mapper not present")
	ErrMountNotPresent  = errors.New("storage: expected mount point not found")
)

func checkDevice(device string) error {
	if device != allowedBackingDevice {
		return fmt.Errorf("%w: device=%q", ErrDeviceNotAllowed, device)
	}
	return nil
}

func checkMapper(mapper string) error {
	if mapper != allowedMapper {
		return fmt.Errorf("%w: mapper=%q", ErrDeviceNotAllowed, mapper)
	}
	return nil
}

func checkMount(mountPoint string) error {
	if mountPoint != allowedMountPoint {
		return fmt.Errorf("%w: mount=%q", ErrDeviceNotAllowed, mountPoint)
	}
	return nil
}
