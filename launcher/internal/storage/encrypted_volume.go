// Package storage provides encrypted volume management for persistent user data.
package storage

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
)

const (
	devicePath = "/dev/nvme0n2"
	luksName   = "userdata"
	mapperPath = "/dev/mapper/userdata"

	// MountPoint is where the encrypted volume is mounted on the host.
	MountPoint = "/mnt/disks/userdata"
	// ContainerMountPoint is the destination path inside the container.
	ContainerMountPoint = "/mnt/disks/userdata"

	// defaultKey is a hardcoded placeholder key for development.
	// TODO: Replace with remote key retrieval.
	defaultKey = "test-key-123"
)

// SetupSecondaryEncryptedVolume sets up persistent storage for user data.
// If a secondary storage device exists, it sets up an encrypted LUKS volume on it.
// On first boot it formats and opens the device; on subsequent boots it detects
// the existing LUKS header and only opens it.
// If no secondary device is found, it falls back to a directory on the boot disk,
// and persistent storage is not unsupported if only boot disk is available.
func SetupSecondaryEncryptedVolume(logger logging.Logger) error {
	logger.Info("SetupSecondaryEncryptedVolume: starting", "device", devicePath, "mount_point", MountPoint)

	if _, err := os.Stat(devicePath); err != nil {
		logger.Info("SetupSecondaryEncryptedVolume: no secondary storage device found at %s, using boot disk for persistent storage", devicePath)
		// No secondary device: create the mount point as a plain directory on the
		// boot disk. The boot disk is already encrypted, so no LUKS setup is needed.
		// We reuse the same MountPoint path so that the container bind mount and
		// USER_DATA_PATH env var work identically regardless of the storage backend.
		if err := os.MkdirAll(MountPoint, 0755); err != nil {
			return fmt.Errorf("failed to create mount point %s on boot disk: %w", MountPoint, err)
		}
		logger.Info("SetupSecondaryEncryptedVolume: mount point ready on boot disk (already encrypted)", "mount_point", MountPoint)
		return nil
	}
	logger.Info("SetupSecondaryEncryptedVolume: secondary storage device found, setting up encrypted volume", "device", devicePath)

	isLuks, err := isLuksDevice(devicePath)
	if err != nil {
		logger.Error("SetupSecondaryEncryptedVolume: failed to check LUKS status", "error", err)
		return fmt.Errorf("failed to check LUKS status: %w", err)
	}

	if !isLuks {
		logger.Info("SetupSecondaryEncryptedVolume: no LUKS header detected, formatting device", "device", devicePath)
		if err := luksFormat(devicePath); err != nil {
			logger.Error("SetupSecondaryEncryptedVolume: luksFormat failed", "error", err)
			return fmt.Errorf("failed to format LUKS device: %w", err)
		}
		logger.Info("SetupSecondaryEncryptedVolume: luksFormat succeeded")

		if err := luksOpen(devicePath, luksName); err != nil {
			logger.Error("SetupSecondaryEncryptedVolume: luksOpen failed after format", "error", err)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("SetupSecondaryEncryptedVolume: luksOpen succeeded", "mapper", mapperPath)

		if err := mkfsExt4(mapperPath); err != nil {
			logger.Error("SetupSecondaryEncryptedVolume: mkfs.ext4 failed", "error", err)
			return fmt.Errorf("failed to create ext4 filesystem: %w", err)
		}
		logger.Info("SetupSecondaryEncryptedVolume: mkfs.ext4 succeeded")
	} else {
		logger.Info("SetupSecondaryEncryptedVolume: LUKS header detected, reusing existing volume", "device", devicePath)
		if err := luksOpen(devicePath, luksName); err != nil {
			logger.Error("SetupSecondaryEncryptedVolume: luksOpen failed", "error", err)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("SetupSecondaryEncryptedVolume: luksOpen succeeded", "mapper", mapperPath)
	}

	if err := os.MkdirAll(MountPoint, 0755); err != nil {
		logger.Error("SetupSecondaryEncryptedVolume: MkdirAll failed", "mount_point", MountPoint, "error", err)
		return fmt.Errorf("failed to create mount point %s: %w", MountPoint, err)
	}
	logger.Info("SetupSecondaryEncryptedVolume: mount point directory ready", "mount_point", MountPoint)

	if err := mount(mapperPath, MountPoint); err != nil {
		logger.Error("SetupSecondaryEncryptedVolume: mount failed", "source", mapperPath, "target", MountPoint, "error", err)
		return fmt.Errorf("failed to mount %s at %s: %w", mapperPath, MountPoint, err)
	}

	logger.Info("SetupSecondaryEncryptedVolume: encrypted volume ready", "mount_point", MountPoint)
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

// luksFormat formats the device with LUKS encryption.
func luksFormat(device string) error {
	cmd := exec.Command("cryptsetup", "luksFormat", "--pbkdf", "pbkdf2", device, "-")
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
