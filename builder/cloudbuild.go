package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	cloudbuild "cloud.google.com/go/cloudbuild/apiv1/v2"
	"cloud.google.com/go/cloudbuild/apiv1/v2/cloudbuildpb"
	"google.golang.org/protobuf/types/known/durationpb"
)

const captureImageIDStepID = "CaptureImageID"

// BuildResult contains the result of a Cloud Build execution.
type BuildResult struct {
	// BuildID is the Cloud Build ID
	BuildID string

	// ResultingImage is the full path to the created image
	ResultingImage string

	// ImageID is the unique GCE image ID (immutable identifier)
	ImageID string

	// Status is the build status
	Status string

	// Duration is how long the build took
	Duration time.Duration
}

// triggerImageBuild triggers the cos-customizer Cloud Build to create the GCE image.
// Unlike the standard cloudbuild.yaml, this version uses a pre-verified launcher from a container image.
// launcherImage is the full image reference (e.g., us-central1-docker.pkg.dev/project/repo/launcher:v1.0.0).
// sourceGeneration is the GCS generation number of the source archive, used to prevent TOCTOU attacks.
func triggerImageBuild(ctx context.Context, config *Config, launcherImage string, sourceGeneration int64) (*BuildResult, error) {
	client, err := cloudbuild.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Build client: %w", err)
	}
	defer client.Close()

	// Build the Cloud Build configuration
	// This is a programmatic version of launcher/cloudbuild.yaml
	// but uses a pre-built launcher container instead of building during the job
	build := &cloudbuildpb.Build{
		Steps: []*cloudbuildpb.BuildStep{
			// Step 1: Pull the launcher container image
			// The launcher is packaged as a container to enable SLSA provenance via Container Analysis
			{
				Name: "gcr.io/cloud-builders/docker",
				Id:   "PullLauncher",
				Args: []string{"pull", launcherImage},
			},
			// Step 2: Extract the launcher binary from the container
			// The container is a FROM scratch image with just the binary at /launcher
			{
				Name:       "gcr.io/cloud-builders/docker",
				Id:         "ExtractLauncher",
				Entrypoint: "/bin/bash",
				Args: []string{
					"-c",
					fmt.Sprintf(`id=$(docker create %s) && docker cp $id:/launcher ./launcher/image/launcher && docker rm $id`, launcherImage),
				},
			},
			// Step 3: Make launcher executable
			{
				Name:       "gcr.io/cloud-builders/gcloud",
				Id:         "ChmodLauncher",
				Entrypoint: "chmod",
				Args:       []string{"+x", "./launcher/image/launcher"},
			},
			// Step 3: Start cos-customizer image build
			{
				Name: "gcr.io/cos-cloud/cos-customizer",
				Id:   "StartImageBuild",
				Args: []string{
					"start-image-build",
					"-build-context=launcher/image",
					fmt.Sprintf("-gcs-bucket=%s", config.StagingBucket),
					"-gcs-workdir=customizer-${BUILD_ID}",
					fmt.Sprintf("-image-name=%s", config.BaseImage),
					fmt.Sprintf("-image-project=%s", config.BaseImageProject),
				},
			},
			// Step 5: Run preload script
			{
				Name: "gcr.io/cos-cloud/cos-customizer",
				Id:   "RunPreload",
				Args: []string{
					"run-script",
					"-script=preload.sh",
					fmt.Sprintf("-env=IMAGE_ENV=%s", config.ImageEnv),
				},
			},
			// Step 6: Seal OEM partition
			{
				Name: "gcr.io/cos-cloud/cos-customizer",
				Id:   "SealOEM",
				Args: []string{"seal-oem"},
			},
			// Step 7: Run fixup script
			{
				Name: "gcr.io/cos-cloud/cos-customizer",
				Id:   "RunFixup",
				Args: []string{
					"run-script",
					"-script=fixup_oem.sh",
				},
			},
			// Step 8: Finish image build
			{
				Name: "gcr.io/cos-cloud/cos-customizer",
				Id:   "FinishImageBuild",
				Args: []string{
					"finish-image-build",
					fmt.Sprintf("-oem-size=%s", config.OEMSize),
					fmt.Sprintf("-disk-size-gb=%d", config.DiskSizeGB),
					fmt.Sprintf("-image-name=%s", config.OutputImageName),
					fmt.Sprintf("-image-family=%s", config.OutputImageFamily),
					fmt.Sprintf("-image-project=%s", config.ProjectID),
					fmt.Sprintf("-zone=%s", config.Zone),
					fmt.Sprintf("-project=%s", config.ProjectID),
				},
			},
			// Step 9: Capture image ID atomically within Cloud Build
			// Uses $BUILDER_OUTPUT/output which Cloud Build reads into buildStepOutputs
			{
				Name:       "gcr.io/cloud-builders/gcloud",
				Id:         captureImageIDStepID,
				Entrypoint: "/bin/bash",
				Args: []string{
					"-c",
					fmt.Sprintf(`gcloud compute images describe %s --project=%s --format='value(id)' > $$BUILDER_OUTPUT/output`,
						config.OutputImageName, config.ProjectID),
				},
			},
		},
		// Source is the repository containing the build scripts
		// The launcher binary is downloaded separately (already verified)
		// Generation pins to exact object version, preventing TOCTOU attacks
		Source: &cloudbuildpb.Source{
			Source: &cloudbuildpb.Source_StorageSource{
				StorageSource: &cloudbuildpb.StorageSource{
					Bucket:     config.StagingBucket,
					Object:     "source.tar.gz",
					Generation: sourceGeneration,
				},
			},
		},
		Timeout: &durationpb.Duration{
			Seconds: config.BuildTimeout,
		},
		Options: &cloudbuildpb.BuildOptions{
			DynamicSubstitutions: true,
		},
	}

	// Create the build
	slog.Info("creating Cloud Build job")
	req := &cloudbuildpb.CreateBuildRequest{
		ProjectId: config.ProjectID,
		Build:     build,
	}

	op, err := client.CreateBuild(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create build: %w", err)
	}

	// Wait for the build to complete
	slog.Info("build started, waiting for completion")
	startTime := time.Now()

	resp, err := op.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("build failed: %w", err)
	}

	duration := time.Since(startTime)

	result := &BuildResult{
		BuildID:        resp.Id,
		Status:         resp.Status.String(),
		Duration:       duration,
		ResultingImage: fmt.Sprintf("projects/%s/global/images/%s", config.ProjectID, config.OutputImageName),
		ImageID:        extractImageID(resp),
	}

	if resp.Status != cloudbuildpb.Build_SUCCESS {
		return result, fmt.Errorf("build finished with status %s", resp.Status.String())
	}

	return result, nil
}

// extractImageID finds the CaptureImageID step and extracts the image ID from its output.
// The image ID is captured atomically within Cloud Build via $BUILDER_OUTPUT/output.
func extractImageID(build *cloudbuildpb.Build) string {
	if build.Results == nil {
		return ""
	}

	// Find the index of the CaptureImageID step
	for i, step := range build.Steps {
		if step.Id == captureImageIDStepID {
			if i < len(build.Results.BuildStepOutputs) {
				return strings.TrimSpace(string(build.Results.BuildStepOutputs[i]))
			}
			break
		}
	}
	return ""
}
