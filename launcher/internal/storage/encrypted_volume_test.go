package storage

import (
	"testing"

	"github.com/Layr-Labs/go-tpm-tools/launcher/internal/logging"
)

func TestConstants(t *testing.T) {
	if MountPoint == "" {
		t.Error("MountPoint should not be empty")
	}
	if ContainerMountPoint == "" {
		t.Error("ContainerMountPoint should not be empty")
	}
	if mapperPath != "/dev/mapper/"+luksName {
		t.Errorf("mapperPath should be /dev/mapper/%s, got %s", luksName, mapperPath)
	}
}

func TestSetupEncryptedVolume_NoDevice(t *testing.T) {
	// SetupEncryptedVolume should return an error when the device does not exist.
	// We rely on the fact that /dev/nvme0n2 does not exist in test environments.
	err := SetupEncryptedVolume(logging.SimpleLogger())
	if err == nil {
		t.Fatal("expected error when device does not exist")
	}
}

func TestIsLuksDevice_NonexistentDevice(t *testing.T) {
	// isLuksDevice should return an error or false for a nonexistent device.
	isLuks, err := isLuksDevice("/dev/nonexistent_device_for_test")
	if err == nil && isLuks {
		t.Error("expected false or error for nonexistent device")
	}
}
