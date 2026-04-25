// Package storage: online grow of the secondary LUKS-encrypted PD.
package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

// pdSizeBytes returns the kernel-visible byte size of the backing PD.
// After a GCP resize, this may still report the old value until the kernel
// rescans the SCSI device — callers use kernelRescanPD first (Task 5).
func pdSizeBytes(ctx context.Context, r commandRunner, device string) (uint64, error) {
	if err := checkDevice(device); err != nil {
		return 0, err
	}
	return runBlockdevGetsize64(ctx, r, device)
}

// mapperSizeBytes returns the current byte size of the LUKS mapper device.
func mapperSizeBytes(ctx context.Context, r commandRunner, mapper string) (uint64, error) {
	if err := checkMapper(mapper); err != nil {
		return 0, err
	}
	return runBlockdevGetsize64(ctx, r, mapper)
}

func runBlockdevGetsize64(ctx context.Context, r commandRunner, path string) (uint64, error) {
	out, err := r.Run(ctx, "blockdev", "--getsize64", path)
	if err != nil {
		return 0, fmt.Errorf("blockdev --getsize64 %s: %w", path, err)
	}
	s := strings.TrimSpace(string(out))
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse blockdev output %q: %w", s, err)
	}
	return n, nil
}
