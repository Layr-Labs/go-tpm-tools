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

// SetupEncryptedVolume sets up an encrypted LUKS volume on the persistent
// storage device. On first boot it formats and opens the device; on subsequent
// boots it detects the existing LUKS header and only opens it.
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

	if !isLuks {
		logger.Info("SetupEncryptedVolume: no LUKS header detected, formatting device", "device", devicePath)
		if err := luksFormat(devicePath); err != nil {
			logger.Error("SetupEncryptedVolume: luksFormat failed", "error", err)
			return fmt.Errorf("failed to format LUKS device: %w", err)
		}
		logger.Info("SetupEncryptedVolume: luksFormat succeeded")

		if err := luksOpen(devicePath, luksName); err != nil {
			logger.Error("SetupEncryptedVolume: luksOpen failed after format", "error", err)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("SetupEncryptedVolume: luksOpen succeeded", "mapper", mapperPath)

		if err := mkfsExt4(mapperPath); err != nil {
			logger.Error("SetupEncryptedVolume: mkfs.ext4 failed", "error", err)
			return fmt.Errorf("failed to create ext4 filesystem: %w", err)
		}
		logger.Info("SetupEncryptedVolume: mkfs.ext4 succeeded")
	} else {
		logger.Info("SetupEncryptedVolume: LUKS header detected, reusing existing volume", "device", devicePath)
		if err := luksOpen(devicePath, luksName); err != nil {
			logger.Error("SetupEncryptedVolume: luksOpen failed", "error", err)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}
		logger.Info("SetupEncryptedVolume: luksOpen succeeded", "mapper", mapperPath)
	}

	if err := os.MkdirAll(MountPoint, 0755); err != nil {
		logger.Error("SetupEncryptedVolume: MkdirAll failed", "mount_point", MountPoint, "error", err)
		return fmt.Errorf("failed to create mount point %s: %w", MountPoint, err)
	}
	logger.Info("SetupEncryptedVolume: mount point directory ready", "mount_point", MountPoint)

	if err := mount(mapperPath, MountPoint); err != nil {
		logger.Error("SetupEncryptedVolume: mount failed", "source", mapperPath, "target", MountPoint, "error", err)
		return fmt.Errorf("failed to mount %s at %s: %w", mapperPath, MountPoint, err)
	}

	logger.Info("SetupEncryptedVolume: encrypted volume ready", "mount_point", MountPoint)
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
