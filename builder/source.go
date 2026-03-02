package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"cloud.google.com/go/storage"
)

const (
	// scriptsDir is where cos-customizer scripts are bundled in the container
	scriptsDir = "/scripts"
	// targetDir is the path structure expected by cos-customizer build context
	targetDir = "launcher/image"
)

// sourceObjectPath returns the GCS object path for the source archive.
// Uses image name to prevent race conditions when building multiple images in parallel.
func sourceObjectPath(config *Config) string {
	return fmt.Sprintf("%s/source.tar.gz", config.OutputImageName)
}

// uploadSource creates a tar.gz archive from the bundled cos-customizer scripts
// and uploads it to the staging bucket. Cloud Build uses this as its source.
// Returns the GCS generation number to prevent TOCTOU attacks.
func uploadSource(ctx context.Context, config *Config) (int64, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return 0, fmt.Errorf("create storage client: %w", err)
	}
	defer client.Close()

	objectPath := sourceObjectPath(config)
	obj := client.Bucket(config.StagingBucket).Object(objectPath)
	w := obj.NewWriter(ctx)
	defer w.Close()

	gw := gzip.NewWriter(w)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Walk the scripts directory and add files to the archive
	err = filepath.Walk(scriptsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if path == scriptsDir {
			return nil
		}

		// Calculate the relative path from scriptsDir
		relPath, err := filepath.Rel(scriptsDir, path)
		if err != nil {
			return err
		}

		// Create the target path (launcher/image/...)
		targetPath := filepath.Join(targetDir, relPath)

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = targetPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// If it's a directory, we're done
		if info.IsDir() {
			return nil
		}

		// Copy file contents
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		return err
	})

	if err != nil {
		return 0, fmt.Errorf("create archive: %w", err)
	}

	// Ensure all data is flushed
	if err := tw.Close(); err != nil {
		return 0, fmt.Errorf("close tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return 0, fmt.Errorf("close gzip: %w", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("upload: %w", err)
	}

	// Get the generation number for the uploaded object
	// This is used to pin Cloud Build to this exact version, preventing TOCTOU attacks
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		return 0, fmt.Errorf("get object attrs: %w", err)
	}

	slog.Info("source uploaded",
		"bucket", config.StagingBucket,
		"object", objectPath,
		"generation", attrs.Generation,
	)
	return attrs.Generation, nil
}
