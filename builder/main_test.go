package main

import (
	"context"
	"os"
	"testing"
)

func TestLoadConfig_RequiredFields(t *testing.T) {
	// Save original env and restore after test
	origEnv := map[string]string{
		"PROJECT_ID":         os.Getenv("PROJECT_ID"),
		"PROJECT_NUMBER":     os.Getenv("PROJECT_NUMBER"),
		"LAUNCHER_ARTIFACT":  os.Getenv("LAUNCHER_ARTIFACT"),
		"BASE_IMAGE":         os.Getenv("BASE_IMAGE"),
		"BASE_IMAGE_PROJECT": os.Getenv("BASE_IMAGE_PROJECT"),
		"OUTPUT_IMAGE_NAME":  os.Getenv("OUTPUT_IMAGE_NAME"),
		"PROVENANCE_BUCKET":  os.Getenv("PROVENANCE_BUCKET"),
		"STAGING_BUCKET":     os.Getenv("STAGING_BUCKET"),
		"IMAGE_ENV":          os.Getenv("IMAGE_ENV"),
		"PCR_CAPTURE_IMAGE":  os.Getenv("PCR_CAPTURE_IMAGE"),
	}
	defer func() {
		for k, v := range origEnv {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	// Set all required fields
	setAllRequired := func() {
		os.Setenv("PROJECT_ID", "test-project")
		os.Setenv("PROJECT_NUMBER", "123456789")
		os.Setenv("LAUNCHER_ARTIFACT", "docker://us-central1/project/launcher/launcher/v1.0.0")
		os.Setenv("BASE_IMAGE", "cos-tdx-123")
		os.Setenv("BASE_IMAGE_PROJECT", "confidential-vm-images")
		os.Setenv("OUTPUT_IMAGE_NAME", "test-image")
		os.Setenv("PROVENANCE_BUCKET", "test-bucket")
		os.Setenv("STAGING_BUCKET", "test-bucket")
		os.Setenv("IMAGE_ENV", "hardened")
		os.Setenv("PCR_CAPTURE_IMAGE", "us-central1-docker.pkg.dev/test/cs-build/pcr-capture:v0.1.0")
	}

	t.Run("all required fields set", func(t *testing.T) {
		setAllRequired()
		config, err := loadConfig(context.Background())
		if err != nil {
			t.Errorf("loadConfig(context.Background()) unexpected error: %v", err)
		}
		if config.ProjectID != "test-project" {
			t.Errorf("ProjectID = %q, want %q", config.ProjectID, "test-project")
		}
	})

	t.Run("missing PROJECT_ID", func(t *testing.T) {
		setAllRequired()
		os.Unsetenv("PROJECT_ID")
		_, err := loadConfig(context.Background())
		if err == nil {
			t.Error("loadConfig(context.Background()) expected error for missing PROJECT_ID")
		}
	})

	t.Run("missing LAUNCHER_ARTIFACT", func(t *testing.T) {
		setAllRequired()
		os.Unsetenv("LAUNCHER_ARTIFACT")
		_, err := loadConfig(context.Background())
		if err == nil {
			t.Error("loadConfig(context.Background()) expected error for missing LAUNCHER_ARTIFACT")
		}
	})
}

func TestLoadConfig_ImageEnv(t *testing.T) {
	// Save and restore env
	origEnv := os.Getenv("IMAGE_ENV")
	defer func() {
		if origEnv == "" {
			os.Unsetenv("IMAGE_ENV")
		} else {
			os.Setenv("IMAGE_ENV", origEnv)
		}
	}()

	setMinimalEnv := func() {
		os.Setenv("PROJECT_ID", "test-project")
		os.Setenv("PROJECT_NUMBER", "123456789")
		os.Setenv("LAUNCHER_ARTIFACT", "docker://us-central1/project/launcher/launcher/v1.0.0")
		os.Setenv("BASE_IMAGE", "cos-tdx-123")
		os.Setenv("BASE_IMAGE_PROJECT", "confidential-vm-images")
		os.Setenv("OUTPUT_IMAGE_NAME", "test-image")
		os.Setenv("PROVENANCE_BUCKET", "test-bucket")
		os.Setenv("STAGING_BUCKET", "test-bucket")
		os.Setenv("PCR_CAPTURE_IMAGE", "us-central1-docker.pkg.dev/test/cs-build/pcr-capture:v0.1.0")
	}

	tests := []struct {
		name    string
		env     string
		wantErr bool
	}{
		{"debug is valid", "debug", false},
		{"hardened is valid", "hardened", false},
		{"empty is invalid", "", true},
		{"other value is invalid", "production", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setMinimalEnv()
			if tt.env == "" {
				os.Unsetenv("IMAGE_ENV")
			} else {
				os.Setenv("IMAGE_ENV", tt.env)
			}
			_, err := loadConfig(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfig(context.Background()) error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Save and restore env
	origEnv := map[string]string{
		"GCA_ENDPOINT":          os.Getenv("GCA_ENDPOINT"),
		"ZONE":                  os.Getenv("ZONE"),
		"OEM_SIZE":              os.Getenv("OEM_SIZE"),
		"DISK_SIZE_GB":          os.Getenv("DISK_SIZE_GB"),
		"BUILD_TIMEOUT_SECONDS": os.Getenv("BUILD_TIMEOUT_SECONDS"),
	}
	defer func() {
		for k, v := range origEnv {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	// Set required fields
	os.Setenv("PROJECT_ID", "test-project")
	os.Setenv("PROJECT_NUMBER", "123456789")
	os.Setenv("LAUNCHER_ARTIFACT", "docker://us-central1/project/launcher/launcher/v1.0.0")
	os.Setenv("BASE_IMAGE", "cos-tdx-123")
	os.Setenv("BASE_IMAGE_PROJECT", "confidential-vm-images")
	os.Setenv("OUTPUT_IMAGE_NAME", "test-image")
	os.Setenv("PROVENANCE_BUCKET", "test-bucket")
	os.Setenv("STAGING_BUCKET", "test-bucket")
	os.Setenv("IMAGE_ENV", "hardened")
	os.Setenv("PCR_CAPTURE_IMAGE", "us-central1-docker.pkg.dev/test/cs-build/pcr-capture:v0.1.0")

	// Clear optional fields
	os.Unsetenv("GCA_ENDPOINT")
	os.Unsetenv("ZONE")
	os.Unsetenv("OEM_SIZE")
	os.Unsetenv("DISK_SIZE_GB")
	os.Unsetenv("BUILD_TIMEOUT_SECONDS")

	config, err := loadConfig(context.Background())
	if err != nil {
		t.Fatalf("loadConfig(context.Background()) error = %v", err)
	}

	// Check defaults
	if config.GCAEndpoint != "https://confidentialcomputing.googleapis.com" {
		t.Errorf("GCAEndpoint = %q, want default", config.GCAEndpoint)
	}
	if config.Zone != "us-central1-a" {
		t.Errorf("Zone = %q, want us-central1-a", config.Zone)
	}
	if config.OEMSize != "500M" {
		t.Errorf("OEMSize = %q, want 500M", config.OEMSize)
	}
	if config.DiskSizeGB != 11 {
		t.Errorf("DiskSizeGB = %d, want 11", config.DiskSizeGB)
	}
	if config.BuildTimeout != 3000 {
		t.Errorf("BuildTimeout = %d, want 3000", config.BuildTimeout)
	}
}

func TestLoadConfig_IntegerParsing(t *testing.T) {
	// Save and restore env
	origDisk := os.Getenv("DISK_SIZE_GB")
	origTimeout := os.Getenv("BUILD_TIMEOUT_SECONDS")
	defer func() {
		if origDisk == "" {
			os.Unsetenv("DISK_SIZE_GB")
		} else {
			os.Setenv("DISK_SIZE_GB", origDisk)
		}
		if origTimeout == "" {
			os.Unsetenv("BUILD_TIMEOUT_SECONDS")
		} else {
			os.Setenv("BUILD_TIMEOUT_SECONDS", origTimeout)
		}
	}()

	setMinimalEnv := func() {
		os.Setenv("PROJECT_ID", "test-project")
		os.Setenv("PROJECT_NUMBER", "123456789")
		os.Setenv("LAUNCHER_ARTIFACT", "docker://us-central1/project/launcher/launcher/v1.0.0")
		os.Setenv("BASE_IMAGE", "cos-tdx-123")
		os.Setenv("BASE_IMAGE_PROJECT", "confidential-vm-images")
		os.Setenv("OUTPUT_IMAGE_NAME", "test-image")
		os.Setenv("PROVENANCE_BUCKET", "test-bucket")
		os.Setenv("STAGING_BUCKET", "test-bucket")
		os.Setenv("IMAGE_ENV", "hardened")
		os.Setenv("PCR_CAPTURE_IMAGE", "us-central1-docker.pkg.dev/test/cs-build/pcr-capture:v0.1.0")
	}

	t.Run("valid DISK_SIZE_GB", func(t *testing.T) {
		setMinimalEnv()
		os.Setenv("DISK_SIZE_GB", "20")
		config, err := loadConfig(context.Background())
		if err != nil {
			t.Fatalf("loadConfig(context.Background()) error = %v", err)
		}
		if config.DiskSizeGB != 20 {
			t.Errorf("DiskSizeGB = %d, want 20", config.DiskSizeGB)
		}
	})

	t.Run("invalid DISK_SIZE_GB", func(t *testing.T) {
		setMinimalEnv()
		os.Setenv("DISK_SIZE_GB", "not-a-number")
		_, err := loadConfig(context.Background())
		if err == nil {
			t.Error("loadConfig(context.Background()) expected error for invalid DISK_SIZE_GB")
		}
	})

	t.Run("valid BUILD_TIMEOUT_SECONDS", func(t *testing.T) {
		setMinimalEnv()
		os.Unsetenv("DISK_SIZE_GB")
		os.Setenv("BUILD_TIMEOUT_SECONDS", "7200")
		config, err := loadConfig(context.Background())
		if err != nil {
			t.Fatalf("loadConfig(context.Background()) error = %v", err)
		}
		if config.BuildTimeout != 7200 {
			t.Errorf("BuildTimeout = %d, want 7200", config.BuildTimeout)
		}
	})

	t.Run("invalid BUILD_TIMEOUT_SECONDS", func(t *testing.T) {
		setMinimalEnv()
		os.Unsetenv("DISK_SIZE_GB")
		os.Setenv("BUILD_TIMEOUT_SECONDS", "not-a-number")
		_, err := loadConfig(context.Background())
		if err == nil {
			t.Error("loadConfig(context.Background()) expected error for invalid BUILD_TIMEOUT_SECONDS")
		}
	})
}
