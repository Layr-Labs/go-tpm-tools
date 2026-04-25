// Package storage: online grow of the secondary LUKS-encrypted PD.
package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// kernelRescanPD asks the kernel to re-read the SCSI capacity of the backing
// PD. On cos-tdx this maps to /sys/block/<devname>/device/rescan.
//
// Contract for callers (poller + boot-time grow):
//   - Best-effort and asynchronous: after this returns, a subsequent
//     blockdev --getsize64 may still observe the old size briefly while the
//     kernel processes the rescan. Callers re-read on the next tick.
//   - Non-fatal on missing sysfs node: returning an error here (e.g. ENOENT
//     on a non-SCSI device or in a test environment) must NOT abort the
//     grow flow; the poller logs and retries.
func kernelRescanPD(device string) error {
	if err := checkDevice(device); err != nil {
		return err
	}
	target, err := filepath.EvalSymlinks(device)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", device, err)
	}
	// Invariant: target resolves to a whole disk (/dev/sdX), not a partition
	// (/dev/sdX1). The secondary PD is raw LUKS with no partition table, so
	// filepath.Base(target) is the sysfs block-device name.
	devName := filepath.Base(target)
	rescanPath := filepath.Join("/sys/block", devName, "device", "rescan")
	return writeRescan(rescanPath)
}

// writeRescan writes "1" to the given sysfs path. This is the mechanism
// backing kernelRescanPD.
//
// SECURITY: This helper performs no path validation. Only call it from
// kernelRescanPD, which gates the device via checkDevice before deriving
// the sysfs path. Any new caller MUST validate its input against the
// allowlist or the guard is meaningless.
func writeRescan(path string) error {
	if err := os.WriteFile(path, []byte("1"), 0o200); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
