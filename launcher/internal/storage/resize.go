package storage

// This file implements online grow of the secondary LUKS-encrypted PD.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
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

// luksMapperName is the canonical short LUKS volume name used with cryptsetup.
// It is deliberately distinct from allowedMapper (which is the /dev/mapper path):
// cryptsetup takes the short name, file operations take the path. mapperPath and
// allowedMapper are now derived from this constant.
const luksMapperName = "userdata"

// luksHeaderBytes is the size of the LUKS2 header that cryptsetup reserves at
// the start of the backing device. With the defaults we use (no --offset, no
// custom --luks2-metadata-size), this is 16 MiB.
//
// After a successful online grow, the mapper is always exactly this much
// smaller than the PD, so the poller must treat a pd-minus-mapper delta up to
// this value as the steady state — otherwise it would re-issue cryptsetup
// resize + resize2fs on every tick forever.
const luksHeaderBytes uint64 = 16 * 1024 * 1024

// luksResize runs `cryptsetup resize <name>`. Online-safe.
//
// Preconditions:
//   - The mapper must already be open (present under /dev/mapper/<name>),
//     so this operates on an active dm entry.
//   - The LUKS passphrase is NOT required: cryptsetup resize only talks
//     to the kernel's active device-mapper entry. This matters for the
//     runtime poller, which does not keep the key in memory.
//
// name is constrained to the package's single LUKS volume (luksMapperName).
func luksResize(ctx context.Context, r commandRunner, name string) error {
	if name != luksMapperName {
		return fmt.Errorf("%w: luks name=%q", ErrDeviceNotAllowed, name)
	}
	if _, err := r.Run(ctx, "cryptsetup", "resize", name); err != nil {
		return fmt.Errorf("cryptsetup resize %s: %w", name, err)
	}
	return nil
}

// resizeExt4 runs `resize2fs <mapper>`. Online-safe on mounted ext4.
//
// Grows the filesystem to fill the underlying block device — no target
// size is passed. Shrinking is out of scope for this package (requires an
// unmount and would break the zero-downtime contract).
func resizeExt4(ctx context.Context, r commandRunner, mapper string) error {
	if err := checkMapper(mapper); err != nil {
		return err
	}
	if _, err := r.Run(ctx, "resize2fs", mapper); err != nil {
		return fmt.Errorf("resize2fs %s: %w", mapper, err)
	}
	return nil
}

// verifyMountedFromMapper confirms the mount point is served by the given
// LUKS mapper. Used before resize2fs so we never grow a filesystem this
// package does not own.
//
// Allowlist order matters: mount and mapper are both validated before any
// subprocess is spawned. If findmnt itself fails (mount missing, binary
// absent, permission denied, etc.), we return ErrMountNotPresent so callers
// can treat "we can't prove this is our mount" and "it is not our mount"
// uniformly as grounds to skip resize.
func verifyMountedFromMapper(ctx context.Context, r commandRunner, mountPoint, mapper string) error {
	if err := checkMount(mountPoint); err != nil {
		return err
	}
	if err := checkMapper(mapper); err != nil {
		return err
	}
	out, err := r.Run(ctx, "findmnt", "-n", "-o", "SOURCE", mountPoint)
	if err != nil {
		return fmt.Errorf("%w: findmnt %s: %v", ErrMountNotPresent, mountPoint, err)
	}
	got := strings.TrimSpace(string(out))
	if got != mapper {
		return fmt.Errorf("%w: mount %s backed by %q, want %q", ErrMountNotPresent, mountPoint, got, mapper)
	}
	return nil
}

// growOnce performs one full online-grow cycle. Idempotent:
//   - noop when pdSize == mapperSize
//   - noop when pdSize <  mapperSize (shrink is not supported; see design spec)
//   - otherwise: verify mount, cryptsetup resize, resize2fs
//
// Errors are returned; callers decide whether to log-and-continue (poller)
// or abort (not applicable today — both callers treat errors as non-fatal).
// This is the runtime variant: it assumes the FS is mounted, and calls
// verifyMountedFromMapper before issuing resize2fs.
//
// Concurrency: callers must serialize invocations. Two concurrent runs
// would issue overlapping `cryptsetup resize` / `resize2fs` commands on
// the same mapper, which is unspecified. Today the boot-time caller runs
// exactly once before the poller starts, and the poller is a single
// goroutine, so no in-process mutex is needed.
func growOnce(ctx context.Context, r commandRunner, logger logging.Logger) error {
	pdSize, err := pdSizeBytes(ctx, r, allowedBackingDevice)
	if err != nil {
		return fmt.Errorf("read pd size: %w", err)
	}
	mapperSize, err := mapperSizeBytes(ctx, r, allowedMapper)
	if err != nil {
		return fmt.Errorf("read mapper size: %w", err)
	}

	// The LUKS2 header occupies the first luksHeaderBytes of the PD, so the
	// mapper's post-grow size is always pdSize - luksHeaderBytes. Anything
	// within that tolerance is the steady state and must be a no-op; only a
	// delta strictly greater indicates the PD was enlarged and we need to
	// grow the mapper and filesystem.
	if pdSize < mapperSize {
		logger.Debug("grow: no-op, pd smaller than mapper (shrink not supported)",
			"pd_size_bytes", pdSize, "mapper_size_bytes", mapperSize)
		return nil
	}
	if pdSize-mapperSize <= luksHeaderBytes {
		logger.Debug("grow: no-op, sizes within LUKS header tolerance",
			"pd_size_bytes", pdSize, "mapper_size_bytes", mapperSize)
		return nil
	}

	logger.Info("grow: pd is larger than mapper, resizing",
		"pd_size_bytes", pdSize, "mapper_size_bytes", mapperSize)

	if err := verifyMountedFromMapper(ctx, r, allowedMountPoint, allowedMapper); err != nil {
		return fmt.Errorf("mount precheck: %w", err)
	}
	if err := luksResize(ctx, r, luksMapperName); err != nil {
		return err
	}
	if err := resizeExt4(ctx, r, allowedMapper); err != nil {
		return err
	}
	logger.Info("grow: resize complete")
	return nil
}

// rescanFn is the rescan hook used by GrowOnce. A var so tests can swap
// it out; production always uses kernelRescanPD.
var rescanFn = kernelRescanPD

// GrowOnce is the package-visible entry point for runtime online grow.
//
// It triggers a kernel rescan of the backing PD (best-effort: a rescan
// error is logged but does not abort the grow — growOnce will still read
// sizes and no-op if the kernel hasn't picked up the new capacity). Then
// it delegates to growOnce with the default runner.
func GrowOnce(ctx context.Context, logger logging.Logger) error {
	if err := rescanFn(allowedBackingDevice); err != nil {
		logger.Debug("kernel rescan failed (continuing)", "error", err)
	}
	return growOnce(ctx, defaultRunner, logger)
}

// growOnceBoot is the boot-time variant of growOnce. It runs AFTER the
// filesystem is mounted — SetupSecondaryEncryptedVolume has already
// opened the LUKS device, (on first boot) mkfs'd it, created the mount
// point, and mounted /dev/mapper/userdata at MountPoint before invoking
// this function. The post-mount ordering is deliberate: resize2fs
// refuses to grow an unmounted ext4 without a prior `e2fsck -f` (ext4
// safety feature), whereas growing a mounted fs is online-safe and
// avoids that requirement. We skip the findmnt-based mount sanity
// check because the mount just succeeded in the same function scope.
//
// Concurrency: serialized by construction (called once per SetupSecondary
// EncryptedVolume invocation, before the poller starts).
func growOnceBoot(ctx context.Context, r commandRunner, logger logging.Logger) error {
	pdSize, err := pdSizeBytes(ctx, r, allowedBackingDevice)
	if err != nil {
		return fmt.Errorf("read pd size: %w", err)
	}
	mapperSize, err := mapperSizeBytes(ctx, r, allowedMapper)
	if err != nil {
		return fmt.Errorf("read mapper size: %w", err)
	}
	// Same LUKS-header tolerance as growOnce: a pd-minus-mapper delta up to
	// luksHeaderBytes is the post-grow steady state, not a signal to resize.
	if pdSize < mapperSize || pdSize-mapperSize <= luksHeaderBytes {
		logger.Debug("grow (boot): no-op",
			"pd_size_bytes", pdSize, "mapper_size_bytes", mapperSize)
		return nil
	}
	logger.Info("grow (boot): pd larger than mapper, resizing",
		"pd_size_bytes", pdSize, "mapper_size_bytes", mapperSize)
	if err := luksResize(ctx, r, luksMapperName); err != nil {
		return err
	}
	if err := resizeExt4(ctx, r, allowedMapper); err != nil {
		return err
	}
	logger.Info("grow (boot): resize complete")
	return nil
}

// GrowOnceBoot is the package-visible entry for the boot-time variant.
// See growOnceBoot for semantics. Uses the default runner and first kicks
// the kernel rescan (best-effort).
func GrowOnceBoot(ctx context.Context, logger logging.Logger) error {
	if err := rescanFn(allowedBackingDevice); err != nil {
		logger.Debug("kernel rescan failed at boot (continuing)", "error", err)
	}
	return growOnceBoot(ctx, defaultRunner, logger)
}
