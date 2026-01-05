package main

import (
	"context"
	"fmt"
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
// Unlike the standard cloudbuild.yaml, this version uses a pre-verified launcher binary.
// launcherGCSPath is the GCS path (gs://...) to the verified launcher binary.
func triggerImageBuild(ctx context.Context, config *Config, launcherGCSPath string) (*BuildResult, error) {
	client, err := cloudbuild.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Build client: %w", err)
	}
	defer client.Close()

	// Build the Cloud Build configuration
	// This is a programmatic version of launcher/cloudbuild.yaml
	// but uses a pre-built launcher instead of building during the job
	build := &cloudbuildpb.Build{
		Steps: []*cloudbuildpb.BuildStep{
			// Step 1: Download pre-verified launcher binary from GCS
			{
				Name:       "gcr.io/cloud-builders/gcloud",
				Id:         "DownloadLauncher",
				Entrypoint: "gcloud",
				Args: []string{
					"storage", "cp",
					launcherGCSPath,
					"./launcher/image/launcher",
				},
			},
			// Step 2: Make launcher executable
			{
				Name:       "gcr.io/cloud-builders/gcloud",
				Id:         "ChmodLauncher",
				Entrypoint: "chmod",
				Args:       []string{"+x", "./launcher/image/launcher"},
			},
			// Note: DownloadExpBinary step removed - we don't have access to
			// gs://confidential-space-images_third-party/confidential_space_experiments
			// Step 3: Start cos-customizer image build
			{
				Name: "gcr.io/cos-cloud/cos-customizer",
				Id:   "StartImageBuild",
				Args: []string{
					"start-image-build",
					"-build-context=launcher/image",
					fmt.Sprintf("-gcs-bucket=%s", config.CloudBuildBucket),
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
					"-env=IMAGE_ENV=hardened", // Default to hardened
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
					"-oem-size=500M",
					"-disk-size-gb=11",
					fmt.Sprintf("-image-name=%s", config.OutputImageName),
					fmt.Sprintf("-image-family=%s", config.OutputImageFamily),
					fmt.Sprintf("-image-project=%s", config.ProjectID),
					// Note: Licenses should be configured based on deployment
					"-zone=us-central1-a",
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
		Source: &cloudbuildpb.Source{
			Source: &cloudbuildpb.Source_StorageSource{
				StorageSource: &cloudbuildpb.StorageSource{
					Bucket: config.CloudBuildBucket,
					Object: "source.tar.gz", // Source code archive
				},
			},
		},
		Timeout: &durationpb.Duration{
			Seconds: 3000, // 50 minutes
		},
		Options: &cloudbuildpb.BuildOptions{
			DynamicSubstitutions: true,
		},
		// Let Cloud Build use its default service account
		// (which should have access to confidential-space-images buckets)
	}

	// Create the build
	log("Creating Cloud Build job...")
	req := &cloudbuildpb.CreateBuildRequest{
		ProjectId: config.ProjectID,
		Build:     build,
	}

	op, err := client.CreateBuild(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create build: %w", err)
	}

	// Wait for the build to complete
	log("Build started, waiting for completion...")
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
