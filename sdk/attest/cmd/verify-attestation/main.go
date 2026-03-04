// verify-attestation verifies a TPM/TEE attestation and outputs claims as JSON.
//
// Usage: verify-attestation <attestation_b64> <challenge_hex> [extra_data_hex]
//
// Exits 0 on success (JSON to stdout), non-zero on failure (errors to stderr).
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
)

// --- Output JSON types (same as parity-dump) ---

type output struct {
	TPMClaims       *tpmJSON       `json:"tpm_claims"`
	TEEClaims       *teeJSON       `json:"tee_claims"`
	ContainerClaims *containerJSON `json:"container_claims"`
}

type tpmJSON struct {
	Platform string            `json:"platform"`
	Hardened bool              `json:"hardened"`
	PCRs     map[string]string `json:"pcrs"`
	GCE      *gceJSON          `json:"gce"`
}

type gceJSON struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber string `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceID    string `json:"instance_id"`
	InstanceName  string `json:"instance_name"`
}

type teeJSON struct {
	Platform string      `json:"platform"`
	TDX      *tdxJSON    `json:"tdx,omitempty"`
	SevSnp   *sevSnpJSON `json:"sevsnp,omitempty"`
}

type tdxJSON struct {
	MRTD       string      `json:"mrtd"`
	RTMR0      string      `json:"rtmr0"`
	RTMR1      string      `json:"rtmr1"`
	RTMR2      string      `json:"rtmr2"`
	RTMR3      string      `json:"rtmr3"`
	TeeTcbSvn  string      `json:"tee_tcb_svn"`
	Attributes tdAttrsJSON `json:"attributes"`
}

type tdAttrsJSON struct {
	Debug         bool `json:"debug"`
	SeptVEDisable bool `json:"sept_ve_disable"`
	PKS           bool `json:"pks"`
	KL            bool `json:"kl"`
	PerfMon       bool `json:"perf_mon"`
}

type sevSnpJSON struct {
	Measurement  string           `json:"measurement"`
	HostData     string           `json:"host_data"`
	CurrentTcb   string           `json:"current_tcb"`
	ReportedTcb  string           `json:"reported_tcb"`
	CommittedTcb string           `json:"committed_tcb"`
	GuestSvn     uint32           `json:"guest_svn"`
	Policy       sevSnpPolicyJSON `json:"policy"`
}

type sevSnpPolicyJSON struct {
	Debug                bool  `json:"debug"`
	MigrateMA            bool  `json:"migrate_ma"`
	SMT                  bool  `json:"smt"`
	ABIMinor             uint8 `json:"abi_minor"`
	ABIMajor             uint8 `json:"abi_major"`
	SingleSocket         bool  `json:"single_socket"`
	CipherTextHidingDRAM bool  `json:"ciphertext_hiding_dram"`
}

type containerJSON struct {
	ImageReference string            `json:"image_reference"`
	ImageDigest    string            `json:"image_digest"`
	ImageID        string            `json:"image_id"`
	RestartPolicy  string            `json:"restart_policy"`
	Args           []string          `json:"args"`
	EnvVars        map[string]string `json:"env_vars"`
}

var pcrIndices = []uint32{0, 4, 8, 9}

func main() {
	// Redirect the default logger to stderr so dependency warnings
	// (e.g. go-tdx-guest) don't pollute JSON on stdout.
	log.SetOutput(os.Stderr)

	// Disk cache replaces the in-memory LRU so collateral
	// (Intel PCS / AMD KDS) survives across subprocess invocations.
	if cacheDir, err := os.UserCacheDir(); err == nil {
		attest.SetCollateralCache(newDiskCache(
			filepath.Join(cacheDir, "go-tpm-tools", "collateral"),
		))
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	outputPath := flag.String("output", "", "write JSON result to this file instead of stdout")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("usage: verify-attestation [-output FILE] <attestation_b64> <challenge_hex> [extra_data_hex]")
	}

	attestBytes, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		return fmt.Errorf("decode attestation base64: %w", err)
	}
	challenge, err := hex.DecodeString(args[1])
	if err != nil {
		return fmt.Errorf("decode challenge hex: %w", err)
	}
	var extraData []byte
	if len(args) == 3 && args[2] != "" {
		extraData, err = hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("decode extra_data hex: %w", err)
		}
	}

	// Parse attestation proto.
	att, err := attest.Parse(attestBytes)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// Run VerifyTPM and VerifyBoundTEE concurrently.
	// Both read from the same immutable *Attestation; safe to call concurrently.
	// The in-memory LRU collateral cache (golang-lru/v2) uses a mutex internally.
	var wg sync.WaitGroup
	var tpmResult *attest.VerifiedTPMAttestation
	var teeResult *attest.VerifiedTEEAttestation
	var tpmErr, teeErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		tpmResult, tpmErr = att.VerifyTPM(challenge, extraData)
	}()

	if att.Platform() != attest.PlatformGCPShieldedVM {
		wg.Add(1)
		go func() {
			defer wg.Done()
			teeResult, teeErr = att.VerifyBoundTEE(challenge, extraData)
		}()
	}

	wg.Wait()

	if tpmErr != nil {
		return fmt.Errorf("VerifyTPM: %w", tpmErr)
	}
	if teeErr != nil {
		return fmt.Errorf("VerifyBoundTEE: %w", teeErr)
	}

	out := output{}

	tpmClaims, err := tpmResult.ExtractTPMClaims(attest.ExtractOptions{PCRIndices: pcrIndices})
	if err != nil {
		return fmt.Errorf("ExtractTPMClaims: %w", err)
	}
	out.TPMClaims = convertTPMClaims(tpmClaims)

	if teeResult != nil {
		teeClaims, err := teeResult.ExtractTEEClaims()
		if err != nil {
			return fmt.Errorf("ExtractTEEClaims: %w", err)
		}
		out.TEEClaims = convertTEEClaims(teeClaims)
	}

	// Extract container claims (optional, no error if absent).
	containerInfo, err := att.ExtractContainerClaims()
	if err == nil {
		out.ContainerClaims = convertContainerClaims(containerInfo)
	}

	jsonBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, append(jsonBytes, '\n'), 0600); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
	} else {
		fmt.Println(string(jsonBytes))
	}
	return nil
}

// --- Conversion functions (same logic as parity-dump) ---

func convertTPMClaims(c *attest.TPMClaims) *tpmJSON {
	t := &tpmJSON{
		Platform: c.Platform.PlatformTag(),
		Hardened: c.Hardened,
		PCRs:     make(map[string]string, len(c.PCRs)),
	}
	for idx, val := range c.PCRs {
		t.PCRs[strconv.FormatUint(uint64(idx), 10)] = hex.EncodeToString(val[:])
	}
	if c.GCE != nil {
		t.GCE = &gceJSON{
			ProjectID:     c.GCE.ProjectID,
			ProjectNumber: strconv.FormatUint(c.GCE.ProjectNumber, 10),
			Zone:          c.GCE.Zone,
			InstanceID:    strconv.FormatUint(c.GCE.InstanceID, 10),
			InstanceName:  c.GCE.InstanceName,
		}
	}
	return t
}

func convertTEEClaims(c *attest.TEEClaims) *teeJSON {
	t := &teeJSON{
		Platform: c.Platform.PlatformTag(),
	}
	if c.TDX != nil {
		t.TDX = &tdxJSON{
			MRTD:      hex.EncodeToString(c.TDX.MRTD[:]),
			RTMR0:     hex.EncodeToString(c.TDX.RTMR0[:]),
			RTMR1:     hex.EncodeToString(c.TDX.RTMR1[:]),
			RTMR2:     hex.EncodeToString(c.TDX.RTMR2[:]),
			RTMR3:     hex.EncodeToString(c.TDX.RTMR3[:]),
			TeeTcbSvn: hex.EncodeToString(c.TDX.TeeTcbSvn[:]),
			Attributes: tdAttrsJSON{
				Debug:         c.TDX.Attributes.Debug,
				SeptVEDisable: c.TDX.Attributes.SeptVEDisable,
				PKS:           c.TDX.Attributes.PKS,
				KL:            c.TDX.Attributes.KL,
				PerfMon:       c.TDX.Attributes.PerfMon,
			},
		}
	}
	if c.SevSnp != nil {
		t.SevSnp = &sevSnpJSON{
			Measurement:  hex.EncodeToString(c.SevSnp.Measurement[:]),
			HostData:     hex.EncodeToString(c.SevSnp.HostData[:]),
			CurrentTcb:   strconv.FormatUint(c.SevSnp.CurrentTcb, 10),
			ReportedTcb:  strconv.FormatUint(c.SevSnp.ReportedTcb, 10),
			CommittedTcb: strconv.FormatUint(c.SevSnp.CommittedTcb, 10),
			GuestSvn:     c.SevSnp.GuestSvn,
			Policy: sevSnpPolicyJSON{
				Debug:                c.SevSnp.Policy.Debug,
				MigrateMA:            c.SevSnp.Policy.MigrateMA,
				SMT:                  c.SevSnp.Policy.SMT,
				ABIMinor:             c.SevSnp.Policy.ABIMinor,
				ABIMajor:             c.SevSnp.Policy.ABIMajor,
				SingleSocket:         c.SevSnp.Policy.SingleSocket,
				CipherTextHidingDRAM: c.SevSnp.Policy.CipherTextHidingDRAM,
			},
		}
	}
	return t
}

func convertContainerClaims(c *attest.ContainerInfo) *containerJSON {
	args := c.Args
	if args == nil {
		args = []string{}
	}
	envVars := c.EnvVars
	if envVars == nil {
		envVars = map[string]string{}
	}
	return &containerJSON{
		ImageReference: c.ImageReference,
		ImageDigest:    c.ImageDigest,
		ImageID:        c.ImageID,
		RestartPolicy:  c.RestartPolicy,
		Args:           args,
		EnvVars:        envVars,
	}
}
