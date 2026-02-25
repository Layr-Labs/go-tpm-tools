// Package storage provides encrypted volume management for persistent user data.
package storage

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
)

const (
	devicePath = "/dev/nvme0n2"
	luksName   = "userdata"
	mapperPath = "/dev/mapper/userdata"

	// dm-clone related device-mapper names.
	cloneName       = "userdata-clone"
	cloneMapperPath = "/dev/mapper/userdata-clone"
	zeroName        = "zero-source"
	zeroMapperPath  = "/dev/mapper/zero-source"
	metadataFile    = "/tmp/dm-clone-meta"

	// cloneRegionSectors is the dm-clone region size in 512-byte sectors.
	// 8 sectors = 4KB, matching typical filesystem block size.
	cloneRegionSectors = 8

	// metadataSizeMB is the size of the dm-clone metadata device in MB.
	// For a 512GB disk with 4KB regions the bitmap is ~16MB.
	// 32MB provides headroom for dm-clone headers at any supported size.
	metadataSizeMB = 32

	// MountPoint is where the encrypted volume is mounted on the host.
	MountPoint = "/mnt/disks/userdata"
	// ContainerMountPoint is the destination path inside the container.
	ContainerMountPoint = "/mnt/disks/userdata"

	// defaultKey is a hardcoded placeholder key for development.
	// TODO: Replace with remote key retrieval.
	defaultKey = "test-key-123"
)

// SetupEncryptedVolume sets up an encrypted LUKS volume with integrity on the
// persistent storage device.
//
// On first boot (no LUKS header) it formats the device with --integrity-no-wipe
// and --integrity-no-journal, then layers dm-clone over dm-zero on top of the
// opened LUKS device. This allows mkfs and mount to proceed immediately: reads
// to unhydrated sectors are served from dm-zero (zeros) while dm-clone hydrates
// the device in the background, initializing all dm-integrity tags.
//
// CRITICAL: nothing must read from /dev/mapper/userdata before dm-clone is set
// up. Any read triggers INTEGRITY AEAD ERRORs on uninitialized sectors, which
// poisons the kernel block layer state and causes subsequent dm-clone hydration
// writes to silently fail. Only blockdev --getsz (an ioctl, not a read) is safe.
//
// On subsequent boots it opens the LUKS device (with journal) and mounts it
// directly. Integrity tags for all sectors written by ext4 are already valid.
func SetupEncryptedVolume(logger logging.Logger) error {
	logger.Info("SetupEncryptedVolume: starting", "device", devicePath, "mount_point", MountPoint)

	fi, err := os.Stat(devicePath)
	if err != nil {
		logger.Error("SetupEncryptedVolume: device not found", "device", devicePath, "error", err)
		return fmt.Errorf("persistent storage device not found at %s: %w", devicePath, err)
	}
	logger.Info("SetupEncryptedVolume: device found", "device", devicePath, "mode", fi.Mode().String())

	isLuks, err := isLuksDevice(devicePath)
	if err != nil {
		logger.Error("SetupEncryptedVolume: failed to check LUKS status", "error", err)
		return fmt.Errorf("failed to check LUKS status: %w", err)
	}
	logger.Info("SetupEncryptedVolume: LUKS check", "is_luks", isLuks)

	if !isLuks {
		// First boot: format, open without journal, set up dm-clone, mkfs,
		// and mount the clone device.
		logger.Info("SetupEncryptedVolume: first boot — formatting device", "device", devicePath)
		if err := luksFormat(devicePath); err != nil {
			logger.Error("SetupEncryptedVolume: luksFormat failed", "error", err)
			logDmesg(logger, "after luksFormat failure")
			return fmt.Errorf("failed to format LUKS device: %w", err)
		}
		logger.Info("SetupEncryptedVolume: luksFormat succeeded")

		if err := luksOpenNoJournal(devicePath, luksName); err != nil {
			logger.Error("SetupEncryptedVolume: luksOpen failed", "error", err)
			logDmesg(logger, "after luksOpen failure")
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("SetupEncryptedVolume: luksOpen succeeded", "mapper", mapperPath)

		// DO NOT read from /dev/mapper/userdata here. Any read triggers
		// INTEGRITY AEAD ERRORs that poison the block layer state.
		// blockdev --getsz is safe (ioctl only, no data read).

		logger.Info("SetupEncryptedVolume: setting up dm-clone for background hydration")
		if err := setupDMClone(logger, mapperPath); err != nil {
			logger.Error("SetupEncryptedVolume: dm-clone setup failed", "error", err)
			logDmesg(logger, "after dm-clone setup failure")
			return fmt.Errorf("failed to set up dm-clone: %w", err)
		}
		logger.Info("SetupEncryptedVolume: dm-clone ready", "clone", cloneMapperPath)

		// Diagnostics — only query dm status, never read from raw device.
		logCmdOutput(logger, "dmsetup status (all)", "dmsetup", "status")

		if err := mkfsExt4(cloneMapperPath); err != nil {
			logger.Error("SetupEncryptedVolume: mkfs.ext4 failed", "error", err)
			logDmesg(logger, "after mkfs.ext4 failure")
			logCmdOutput(logger, "dmsetup status after mkfs failure", "dmsetup", "status")
			return fmt.Errorf("failed to create ext4 filesystem: %w", err)
		}
		logger.Info("SetupEncryptedVolume: mkfs.ext4 succeeded")

		if err := os.MkdirAll(MountPoint, 0755); err != nil {
			return fmt.Errorf("failed to create mount point %s: %w", MountPoint, err)
		}
		if err := mount(cloneMapperPath, MountPoint); err != nil {
			logger.Error("SetupEncryptedVolume: mount failed", "source", cloneMapperPath, "target", MountPoint, "error", err)
			logDmesg(logger, "after mount failure")
			return fmt.Errorf("failed to mount %s at %s: %w", cloneMapperPath, MountPoint, err)
		}
	} else {
		// Subsequent boot: open with journal (full crash consistency) and
		// mount directly. All integrity tags were initialized on first boot.
		logger.Info("SetupEncryptedVolume: subsequent boot — opening existing volume", "device", devicePath)
		if err := luksOpen(devicePath, luksName); err != nil {
			logger.Error("SetupEncryptedVolume: luksOpen failed", "error", err)
			logDmesg(logger, "after luksOpen failure")
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("SetupEncryptedVolume: luksOpen succeeded", "mapper", mapperPath)

		if err := os.MkdirAll(MountPoint, 0755); err != nil {
			return fmt.Errorf("failed to create mount point %s: %w", MountPoint, err)
		}
		if err := mount(mapperPath, MountPoint); err != nil {
			logger.Error("SetupEncryptedVolume: mount failed", "source", mapperPath, "target", MountPoint, "error", err)
			logDmesg(logger, "after mount failure")
			return fmt.Errorf("failed to mount %s at %s: %w", mapperPath, MountPoint, err)
		}
	}

	logger.Info("SetupEncryptedVolume: encrypted volume ready", "mount_point", MountPoint)
	return nil
}

// setupDMClone creates a dm-clone device that layers dm-zero (as source) over
// the given destination device. Reads to unhydrated regions return zeros from
// dm-zero; writes and background hydration go to the destination, initializing
// dm-integrity tags. This avoids blocking boot on a full-disk wipe.
//
// Device stack:
//
//	/dev/mapper/userdata-clone  (dm-clone — mount this)
//	  ├── source: /dev/mapper/zero-source  (dm-zero, returns zeros)
//	  └── dest:   /dev/mapper/userdata     (dm-crypt + dm-integrity)
func setupDMClone(logger logging.Logger, destDevice string) error {
	// Get destination device size in 512-byte sectors.
	// blockdev --getsz is an ioctl — it does NOT read data from the device,
	// so it's safe to call on an uninitialized integrity device.
	sectors, err := getDeviceSectors(destDevice)
	if err != nil {
		return fmt.Errorf("failed to get device size: %w", err)
	}
	logger.Info("setupDMClone: device size", "device", destDevice, "sectors", sectors)

	// Create dm-zero source device.
	zeroTable := fmt.Sprintf("0 %d zero", sectors)
	logger.Info("setupDMClone: creating dm-zero", "name", zeroName, "table", zeroTable)
	if err := dmsetupCreate(zeroName, zeroTable); err != nil {
		return fmt.Errorf("failed to create dm-zero device: %w", err)
	}
	logger.Info("setupDMClone: dm-zero created", "device", zeroMapperPath)

	// Create metadata device backed by a loop device.
	loopDev, err := createMetadataDevice(metadataFile, metadataSizeMB)
	if err != nil {
		return fmt.Errorf("failed to create metadata device: %w", err)
	}
	logger.Info("setupDMClone: metadata device created", "loop", loopDev, "size_mb", metadataSizeMB)

	// Create dm-clone.
	// Table: clone <metadata_dev> <dest_dev> <source_dev> <region_size> [features]
	cloneTable := fmt.Sprintf("0 %d clone %s %s %s %d 0",
		sectors, loopDev, destDevice, zeroMapperPath, cloneRegionSectors)
	logger.Info("setupDMClone: creating dm-clone", "name", cloneName, "table", cloneTable)
	if err := dmsetupCreate(cloneName, cloneTable); err != nil {
		return fmt.Errorf("failed to create dm-clone device: %w", err)
	}

	// Log dm-clone status (shows hydration progress).
	logCmdOutput(logger, "dm-clone initial status", "dmsetup", "status", cloneName)

	return nil
}

// logCmdOutput runs a command and logs its combined stdout+stderr output.
// Failures are logged but not returned — this is for diagnostics only.
func logCmdOutput(logger logging.Logger, label string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Info("diagnostic: "+label, "error", err, "output", strings.TrimSpace(string(out)))
	} else {
		logger.Info("diagnostic: "+label, "output", strings.TrimSpace(string(out)))
	}
}

// logDmesg logs the last 30 lines of dmesg for diagnosing kernel-level errors.
func logDmesg(logger logging.Logger, context string) {
	cmd := exec.Command("dmesg")
	out, err := cmd.Output()
	if err != nil {
		logger.Error("dmesg capture failed", "context", context, "error", err)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	start := 0
	if len(lines) > 30 {
		start = len(lines) - 30
	}
	logger.Info("dmesg (last 30 lines)", "context", context, "output", strings.Join(lines[start:], "\n"))
}

// getDeviceSectors returns the size of a block device in 512-byte sectors.
func getDeviceSectors(device string) (uint64, error) {
	cmd := exec.Command("blockdev", "--getsz", device)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("%w: %s", err, stderr.String())
	}
	s := strings.TrimSpace(stdout.String())
	sectors, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse sector count %q: %w", s, err)
	}
	return sectors, nil
}

// createMetadataDevice creates a zeroed file of the given size and attaches it
// as a loop device. The file is stored on tmpfs — dm-clone metadata is only
// needed on first boot while hydration is in progress.
func createMetadataDevice(path string, sizeMB int) (string, error) {
	// Create zeroed metadata file. dm-clone requires the metadata device to be
	// zero-filled for a fresh hydration bitmap. Using dd to guarantee zeros.
	cmd := exec.Command("dd", "if=/dev/zero", "of="+path, "bs=1M", fmt.Sprintf("count=%d", sizeMB))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to create metadata file: %w: %s", err, stderr.String())
	}

	// Verify the file was created and is the right size.
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("metadata file not found after creation: %w", err)
	}
	expectedSize := int64(sizeMB) * 1024 * 1024
	if fi.Size() != expectedSize {
		return "", fmt.Errorf("metadata file size mismatch: got %d, want %d", fi.Size(), expectedSize)
	}

	// Attach as loop device.
	cmd = exec.Command("losetup", "--find", "--show", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr.Reset()
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to create loop device: %w: %s", err, stderr.String())
	}
	loopDev := strings.TrimSpace(stdout.String())
	if loopDev == "" {
		return "", fmt.Errorf("losetup returned empty device path")
	}
	return loopDev, nil
}

// dmsetupCreate creates a device-mapper device with the given name and table.
func dmsetupCreate(name, table string) error {
	cmd := exec.Command("dmsetup", "create", name, "--table", table)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// isLuksDevice checks whether the device has a LUKS header.
func isLuksDevice(device string) (bool, error) {
	cmd := exec.Command("cryptsetup", "isLuks", device)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Non-zero exit code means it's not a LUKS device.
			if exitErr.ExitCode() != 0 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

// luksFormat formats the device with LUKS and hmac-sha256 integrity.
//
// --integrity-no-wipe skips the full-disk integrity tag initialization. Without
// it, cryptsetup must zero every integrity tag on the device, which creates
// temporary device-mapper entries ("temporary-cryptsetup-*") and can take hours
// on large disks. The caller is responsible for initializing integrity tags
// (e.g., via dm-clone background hydration) before reading unwritten sectors.
func luksFormat(device string) error {
	cmd := exec.Command("cryptsetup", "luksFormat", "--integrity", "hmac-sha256", "--integrity-no-wipe", "--integrity-no-journal", "--pbkdf", "pbkdf2", device, "-")
	cmd.Stdin = strings.NewReader(defaultKey)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// luksOpen opens a LUKS device with the given name.
func luksOpen(device, name string) error {
	cmd := exec.Command("cryptsetup", "luksOpen", device, name, "-")
	cmd.Stdin = strings.NewReader(defaultKey)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// luksOpenNoJournal opens a LUKS device with integrity journal disabled.
// This avoids read-before-write on uninitialized integrity tags during first boot.
func luksOpenNoJournal(device, name string) error {
	cmd := exec.Command("cryptsetup", "luksOpen", "--integrity-no-journal", device, name, "-")
	cmd.Stdin = strings.NewReader(defaultKey)
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
