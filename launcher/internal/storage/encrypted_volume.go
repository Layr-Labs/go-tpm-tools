// Package storage provides encrypted volume management for persistent user data.
package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
)

const (
	luksName   = luksMapperName
	mapperPath = "/dev/mapper/" + luksMapperName

	// MountPoint is where the encrypted volume is mounted on the host.
	MountPoint = "/mnt/disks/userdata"
	// ContainerMountPoint is the destination path inside the container.
	ContainerMountPoint = "/mnt/disks/userdata"
)

const secondaryDevicePath = "/dev/disk/by-id/google-persistent_storage_1"

// secondaryDeviceProbeTimeout bounds how long findSecondaryDevice waits for
// the device node to appear before giving up and falling back to the boot
// disk. GCE PD attach is asynchronous: when the orchestrator provisions a VM
// with an attached PD, the udev event that creates
// /dev/disk/by-id/google-persistent_storage_1 can lag the launcher's startup
// by several seconds. Without polling, the launcher's single os.Stat racing
// against udev frequently misses the disk on fresh deploys, falls back to
// the boot-disk path, and the user's data ends up on a non-persistent
// stateful partition that's wiped on the next reboot.
//
// 30s is a balance between two failure modes: long enough to absorb the
// observed 5–15s GCE attach latency, short enough that a deploy with NO
// secondary disk attached doesn't add meaningful boot time on the
// boot-disk fallback path. The orchestrator's readiness wait is 10 minutes
// so this is well within budget.
const secondaryDeviceProbeTimeout = 30 * time.Second

// LateAttachDeviceTimeout bounds how long the AwaitLateAttach path waits for
// the device. It matches the orchestrator's prewarm-detach attach budget:
// when await-late-attach metadata is set, the orchestrator waits for the
// launcher to emit ECLOUD_AWAITING_USERDATA on serial, then issues AttachPD.
// That round trip plus GCE's PD attach latency can take several minutes, so
// we wait long here. If the device never appears within this budget, it's
// a real failure — the orchestrator either crashed mid-upgrade or never
// sent AttachPD. There is deliberately NO boot-disk fallback here: the
// operator opted in to a contract where the PD WILL arrive, so a missing
// device after this timeout must surface as an error rather than be
// papered over with a non-persistent partition.
const LateAttachDeviceTimeout = 5 * time.Minute

// secondaryDeviceProbeInterval is how often findSecondaryDevice checks for
// the device while waiting. Tighter than the timeout so a fast attach
// (under a second) is observed promptly. Shared between the synchronous
// and late-attach paths since both want low-latency detection.
const secondaryDeviceProbeInterval = 500 * time.Millisecond

// findSecondaryDevice returns the device path if the secondary storage
// device exists, or empty string if it doesn't appear within
// secondaryDeviceProbeTimeout.
//
// Polling is necessary because GCE PD attach is asynchronous: the disk is
// declared attached at the API level before the kernel's udev rules have
// finished publishing the /dev/disk/by-id/* symlink. A single os.Stat
// races against udev and frequently returns ENOENT on fresh deploys even
// when a PD is attached. Falling back to the boot disk in that case
// silently routes user data to a non-persistent partition.
//
// findSecondaryDevice is split into a thin wrapper around findSecondaryDeviceWith
// so tests can inject a fake clock + stat function and exercise the poll
// loop without touching the real filesystem or sleeping for 30s.
func findSecondaryDevice(ctx context.Context, logger logging.Logger) string {
	return findSecondaryDeviceWith(ctx, logger, os.Stat, time.NewTicker, secondaryDeviceProbeTimeout)
}

// statFunc abstracts os.Stat so unit tests can inject deterministic
// "device appears after N polls" behavior.
type statFunc func(string) (os.FileInfo, error)

// tickerFunc abstracts time.NewTicker so unit tests can drive the poll
// cadence with a synthetic clock.
type tickerFunc func(time.Duration) *time.Ticker

func findSecondaryDeviceWith(ctx context.Context, logger logging.Logger, stat statFunc, newTicker tickerFunc, timeout time.Duration) string {
	// Honor an already-cancelled parent ctx before doing any work. The
	// fast-path stat below would otherwise "succeed" (return a device
	// path) even when the caller has signalled cancel, because the
	// stat doesn't consult ctx — only the slow path's select does. This
	// keeps the cancel contract uniform across both paths.
	if ctx.Err() != nil {
		return ""
	}

	// Fast path: the device is already present (no race; e.g. VM was
	// rebooted with the PD already attached). Avoids the first
	// secondaryDeviceProbeInterval of latency on the common case.
	if _, err := stat(secondaryDevicePath); err == nil {
		return secondaryDevicePath
	}

	logger.Info("findSecondaryDevice: device not yet present, polling",
		"device", secondaryDevicePath,
		"timeout", timeout.String(),
		"interval", secondaryDeviceProbeInterval.String(),
	)

	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := newTicker(secondaryDeviceProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadlineCtx.Done():
			logger.Info("findSecondaryDevice: device did not appear before timeout, falling back to boot disk",
				"device", secondaryDevicePath,
				"timeout", timeout.String(),
			)
			return ""
		case <-ticker.C:
			if _, err := stat(secondaryDevicePath); err == nil {
				logger.Info("findSecondaryDevice: device appeared", "device", secondaryDevicePath)
				return secondaryDevicePath
			}
		}
	}
}

// MnemonicProvider is a function that fetches the BIP39 mnemonic from KMS.
// It is only called when a secondary storage device is found and encryption
// is needed — avoiding unnecessary KMS calls when no disk is attached.
type MnemonicProvider func() (string, error)

// SetupSecondaryEncryptedVolume sets up persistent storage for user data
// SYNCHRONOUSLY at boot. It polls briefly for the secondary device (see
// secondaryDeviceProbeTimeout) to absorb the GCE attach race; if the
// device never appears, it falls back to a directory on the boot disk
// and does not call mnemonicProvider.
//
// Use this for the standard launch path where the orchestrator attaches
// the PD at provision time. For the prewarm-detach upgrade path where
// the orchestrator delays AttachPD until the new VM signals readiness,
// use SetupSecondaryEncryptedVolumeLateAttach instead.
//
// On first boot with a secondary device, formats and opens the device;
// on subsequent boots, detects the existing LUKS header and only opens it.
func SetupSecondaryEncryptedVolume(ctx context.Context, logger logging.Logger, mnemonicProvider MnemonicProvider) error {
	logger.Info("SetupSecondaryEncryptedVolume: starting", "mount_point", MountPoint)

	devicePath := findSecondaryDevice(ctx, logger)
	if devicePath == "" {
		logger.Info("SetupSecondaryEncryptedVolume: no secondary storage device found, using boot disk for persistent storage")
		// No secondary device: create the mount point as a plain directory on the
		// boot disk. The boot disk is already encrypted, so no LUKS setup is needed.
		// We reuse the same MountPoint path so that the container bind mount and
		// USER_PERSISTENT_DATA_PATH env var work identically regardless of the storage backend.
		if err := os.MkdirAll(MountPoint, 0755); err != nil {
			return fmt.Errorf("failed to create mount point %s on boot disk: %w", MountPoint, err)
		}
		logger.Info("SetupSecondaryEncryptedVolume: mount point ready on boot disk (already encrypted)", "mount_point", MountPoint)
		return nil
	}

	return setupLUKSOnDevice(ctx, logger, mnemonicProvider, devicePath)
}

// SetupSecondaryEncryptedVolumeLateAttach is the prewarm-detach variant of
// SetupSecondaryEncryptedVolume. It expects the device NOT to exist at call
// time (the orchestrator hasn't run AttachPD yet) and waits up to
// LateAttachDeviceTimeout for it to appear. There is no boot-disk fallback:
// in this mode, the launcher knows a PD is supposed to land, so a missing
// device after the timeout is a real failure that should stop the workload.
//
// This call is SYNCHRONOUS. Callers (the launcher's container_runner)
// must invoke it BEFORE starting the user container — emitting
// ECLOUD_AWAITING_USERDATA on serial first so the orchestrator knows to
// run AttachPD, then waiting for the device, doing LUKS+mount, and only
// then starting the container. Running it after container start would
// leave the bind mount source empty when the container reads it.
func SetupSecondaryEncryptedVolumeLateAttach(ctx context.Context, logger logging.Logger, mnemonicProvider MnemonicProvider) error {
	logger.Info("SetupSecondaryEncryptedVolumeLateAttach: starting", "mount_point", MountPoint, "timeout", LateAttachDeviceTimeout.String())

	devicePath := findSecondaryDeviceWith(ctx, logger, os.Stat, time.NewTicker, LateAttachDeviceTimeout)
	if devicePath == "" {
		// No fallback: the orchestrator promised an attach and failed to
		// deliver. Surface the failure so the launcher returns an error
		// and the orchestrator's readiness wait reports the underlying
		// problem rather than papering it over with a stateful-partition
		// fallback.
		return fmt.Errorf("late-attach: secondary device %s did not appear within %s", secondaryDevicePath, LateAttachDeviceTimeout)
	}

	return setupLUKSOnDevice(ctx, logger, mnemonicProvider, devicePath)
}

// setupLUKSOnDevice runs the LUKS-format-or-open + mount sequence shared by
// both SetupSecondaryEncryptedVolume and SetupSecondaryEncryptedVolumeLateAttach.
// The caller is responsible for verifying the device exists.
func setupLUKSOnDevice(ctx context.Context, logger logging.Logger, mnemonicProvider MnemonicProvider, devicePath string) error {
	logger.Info("setupLUKSOnDevice: secondary storage device found, setting up encrypted volume", "device", devicePath)

	// Fetch mnemonic and derive encryption key only when a secondary device
	// is present. This avoids calling the KMS unnecessarily and sidesteps the
	// chicken-and-egg problem (KMS needs PCR allowlisting, which requires
	// running a workload first).
	logger.Info("setupLUKSOnDevice: fetching mnemonic from KMS")
	mnemonic, err := mnemonicProvider()
	if err != nil {
		return fmt.Errorf("failed to fetch mnemonic for disk encryption: %w", err)
	}

	storageKeyBytes, err := DeriveStorageKey(mnemonic)
	if err != nil {
		return fmt.Errorf("failed to derive storage key from mnemonic: %w", err)
	}
	encryptionKey := hex.EncodeToString(storageKeyBytes)
	ZeroBytes(storageKeyBytes)

	isLuks, err := isLuksDevice(devicePath)
	if err != nil {
		logger.Error("setupLUKSOnDevice: failed to check LUKS status", "error", err)
		return fmt.Errorf("failed to check LUKS status: %w", err)
	}

	if !isLuks {
		logger.Info("setupLUKSOnDevice: no LUKS header detected, formatting device", "device", devicePath)
		if err := luksFormat(devicePath, encryptionKey); err != nil {
			logger.Error("setupLUKSOnDevice: luksFormat failed", "error", err)
			return fmt.Errorf("failed to format LUKS device: %w", err)
		}
		logger.Info("setupLUKSOnDevice: luksFormat succeeded")

		if err := luksOpen(devicePath, luksName, encryptionKey); err != nil {
			logger.Error("setupLUKSOnDevice: luksOpen failed after format", "error", err)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("setupLUKSOnDevice: luksOpen succeeded", "mapper", mapperPath)

		if err := mkfsExt4(mapperPath); err != nil {
			logger.Error("setupLUKSOnDevice: mkfs.ext4 failed", "error", err)
			return fmt.Errorf("failed to create ext4 filesystem: %w", err)
		}
		logger.Info("setupLUKSOnDevice: mkfs.ext4 succeeded")
	} else {
		logger.Info("setupLUKSOnDevice: LUKS header detected, reusing existing volume", "device", devicePath)
		if err := luksOpen(devicePath, luksName, encryptionKey); err != nil {
			logger.Error("setupLUKSOnDevice: luksOpen failed", "error", err)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("setupLUKSOnDevice: luksOpen succeeded", "mapper", mapperPath)
	}

	if err := os.MkdirAll(MountPoint, 0755); err != nil {
		logger.Error("setupLUKSOnDevice: MkdirAll failed", "mount_point", MountPoint, "error", err)
		return fmt.Errorf("failed to create mount point %s: %w", MountPoint, err)
	}
	logger.Info("setupLUKSOnDevice: mount point directory ready", "mount_point", MountPoint)

	if err := mount(mapperPath, MountPoint); err != nil {
		logger.Error("setupLUKSOnDevice: mount failed", "source", mapperPath, "target", MountPoint, "error", err)
		return fmt.Errorf("failed to mount %s at %s: %w", mapperPath, MountPoint, err)
	}

	// Best-effort online grow on boot: if the PD was enlarged while the VM
	// was off, bring the LUKS mapper and ext4 up to size AFTER mount.
	// resize2fs refuses to grow an unmounted ext4 without a prior `e2fsck -f`
	// (safety feature); growing a mounted fs is online-safe and skips that
	// requirement. Failure here is non-fatal; the runtime poller will retry.
	if err := GrowOnceBoot(ctx, logger); err != nil {
		logger.Error("setupLUKSOnDevice: boot-time grow failed, continuing; poller will retry", "error", err)
	}

	logger.Info("setupLUKSOnDevice: encrypted volume ready", "mount_point", MountPoint)
	return nil
}

// CleanupEncryptedVolume tears down the LUKS volume + mount that
// SetupSecondaryEncryptedVolume / SetupSecondaryEncryptedVolumeLateAttach
// brought up, in the order required for safe PD detach: sync, umount,
// cryptsetup close. Each step is best-effort and idempotent — failures
// are logged but don't abort the sequence, since the orchestrator's
// post-detach cleanup is the backstop for any leftover mapper state.
//
// Intended for the prewarm-detach drain path: after the user container
// exits (or on launcher shutdown), the launcher calls this so the PD
// can be detached cleanly. The user-container script can't do this work
// itself because the script's container lacks CAP_SYS_ADMIN, which umount
// and cryptsetup require.
func CleanupEncryptedVolume(ctx context.Context, logger logging.Logger) {
	// sync before umount to flush any pending writes from the user
	// container's late-buffered I/O. Best-effort: if sync fails the
	// kernel will still flush before umount, so this is belt-and-braces.
	if out, err := exec.CommandContext(ctx, "sync").CombinedOutput(); err != nil {
		logger.Warn("CleanupEncryptedVolume: sync failed", "error", err, "output", string(out))
	}

	// umount the bind-source first. If nothing is mounted, this returns
	// a non-zero "not mounted" exit which we treat as success — there's
	// no portable way in a Go child process to read /proc/self/mountinfo
	// safely on cos-tdx without inheriting unrelated mounts.
	if out, err := exec.CommandContext(ctx, "umount", MountPoint).CombinedOutput(); err != nil {
		logger.Warn("CleanupEncryptedVolume: umount returned non-zero (treating as already-unmounted)", "mount_point", MountPoint, "error", err, "output", string(out))
	} else {
		logger.Info("CleanupEncryptedVolume: umount succeeded", "mount_point", MountPoint)
	}

	// cryptsetup close releases the dm-crypt mapping. Same idempotency
	// note as above: if the mapper isn't open this returns non-zero.
	if out, err := exec.CommandContext(ctx, "cryptsetup", "close", luksName).CombinedOutput(); err != nil {
		logger.Warn("CleanupEncryptedVolume: cryptsetup close returned non-zero (treating as already-closed)", "name", luksName, "error", err, "output", string(out))
	} else {
		logger.Info("CleanupEncryptedVolume: cryptsetup close succeeded", "name", luksName)
	}
}

// isLuksDevice checks whether the device has a LUKS header.
func isLuksDevice(device string) (bool, error) {
	cmd := exec.Command("cryptsetup", "isLuks", device)
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Non-zero exit code means it's not a LUKS device.
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// luksFormat formats the device with LUKS encryption.
func luksFormat(device string, key string) error {
	cmd := exec.Command("cryptsetup", "luksFormat", "--pbkdf", "pbkdf2", device, "-")
	cmd.Stdin = strings.NewReader(key)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// luksOpen opens a LUKS device with the given name.
//
// --disable-keyring stores the volume key inside dm-crypt's kernel state
// only, not in the user keyring. This is required so that later
// `cryptsetup resize` calls (issued from GrowOnce / GrowOnceBoot) can
// grow the mapper without re-authenticating via the passphrase — the
// launcher does not keep the mnemonic-derived key in memory after open.
// On cos-tdx (cryptsetup >= 2.6) the keyring is the default and `resize`
// refuses to operate without a passphrase when it's active.
func luksOpen(device, name string, key string) error {
	cmd := exec.Command("cryptsetup", "luksOpen", "--disable-keyring", device, name, "-")
	cmd.Stdin = strings.NewReader(key)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// mkfsExt4 creates an ext4 filesystem on the given device.
func mkfsExt4(device string) error {
	cmd := exec.Command("mkfs.ext4", device)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// mount mounts the source device at the given target.
func mount(source, target string) error {
	cmd := exec.Command("mount", source, target)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}
