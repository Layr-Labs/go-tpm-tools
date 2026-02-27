// parity-dump generates a golden JSON file from the Go SDK for cross-SDK parity testing.
//
// Usage: go run ./sdk/attest/cmd/parity-dump
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
)

// --- Input (same format as attestations.json) ---

type testVectorJSON struct {
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Hardened    bool   `json:"hardened"`
	Attestation string `json:"attestation"` // base64
	Challenge   string `json:"challenge"`   // hex
	ExtraData   string `json:"extra_data"`  // hex
}

// --- Output: golden parity record ---

type parityRecord struct {
	Name            string           `json:"name"`
	TPMClaims       *parityTPM       `json:"tpm_claims"`
	TEEClaims       *parityTEE       `json:"tee_claims"`       // null for Shielded VM
	ContainerClaims *parityContainer `json:"container_claims"` // null if no CEL
}

type parityTPM struct {
	Platform string            `json:"platform"`
	Hardened bool              `json:"hardened"`
	PCRs     map[string]string `json:"pcrs"` // decimal key → hex value
	GCE      *parityGCE        `json:"gce"`  // null if no GCE info
}

type parityGCE struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber string `json:"project_number"` // decimal string
	Zone          string `json:"zone"`
	InstanceID    string `json:"instance_id"` // decimal string
	InstanceName  string `json:"instance_name"`
}

type parityTEE struct {
	Platform string        `json:"platform"`
	TDX      *parityTDX    `json:"tdx,omitempty"`
	SevSnp   *paritySevSnp `json:"sevsnp,omitempty"`
}

type parityTDX struct {
	MRTD       string        `json:"mrtd"`
	RTMR0      string        `json:"rtmr0"`
	RTMR1      string        `json:"rtmr1"`
	RTMR2      string        `json:"rtmr2"`
	RTMR3      string        `json:"rtmr3"`
	TeeTcbSvn  string        `json:"tee_tcb_svn"`
	Attributes parityTDAttrs `json:"attributes"`
}

type parityTDAttrs struct {
	Debug         bool `json:"debug"`
	SeptVEDisable bool `json:"sept_ve_disable"`
	PKS           bool `json:"pks"`
	KL            bool `json:"kl"`
	PerfMon       bool `json:"perf_mon"`
}

type paritySevSnp struct {
	Measurement  string             `json:"measurement"`
	HostData     string             `json:"host_data"`
	CurrentTcb   string             `json:"current_tcb"`   // decimal string
	ReportedTcb  string             `json:"reported_tcb"`  // decimal string
	CommittedTcb string             `json:"committed_tcb"` // decimal string
	GuestSvn     uint32             `json:"guest_svn"`
	Policy       paritySevSnpPolicy `json:"policy"`
}

type paritySevSnpPolicy struct {
	Debug                bool  `json:"debug"`
	MigrateMA            bool  `json:"migrate_ma"`
	SMT                  bool  `json:"smt"`
	ABIMinor             uint8 `json:"abi_minor"`
	ABIMajor             uint8 `json:"abi_major"`
	SingleSocket         bool  `json:"single_socket"`
	CipherTextHidingDRAM bool  `json:"ciphertext_hiding_dram"`
}

type parityContainer struct {
	ImageReference string            `json:"image_reference"`
	ImageDigest    string            `json:"image_digest"`
	ImageID        string            `json:"image_id"`
	RestartPolicy  string            `json:"restart_policy"`
	Args           []string          `json:"args"`
	EnvVars        map[string]string `json:"env_vars"`
}

var pcrIndices = []uint32{0, 4, 8, 9}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	data, err := os.ReadFile("sdk/testdata/attestations.json")
	if err != nil {
		return fmt.Errorf("read test vectors: %w", err)
	}

	var vectors []testVectorJSON
	if err := json.Unmarshal(data, &vectors); err != nil {
		return fmt.Errorf("parse test vectors: %w", err)
	}

	records := make([]parityRecord, 0, len(vectors))
	for _, v := range vectors {
		rec, err := processVector(v)
		if err != nil {
			return fmt.Errorf("vector %q: %w", v.Name, err)
		}
		records = append(records, rec)
	}

	out, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal golden: %w", err)
	}

	if err := os.WriteFile("sdk/testdata/parity-golden.json", append(out, '\n'), 0644); err != nil {
		return fmt.Errorf("write golden: %w", err)
	}

	fmt.Printf("wrote %d records to sdk/testdata/parity-golden.json\n", len(records))
	return nil
}

func processVector(v testVectorJSON) (parityRecord, error) {
	attestBytes, err := base64.StdEncoding.DecodeString(v.Attestation)
	if err != nil {
		return parityRecord{}, fmt.Errorf("decode attestation: %w", err)
	}
	challenge, err := hex.DecodeString(v.Challenge)
	if err != nil {
		return parityRecord{}, fmt.Errorf("decode challenge: %w", err)
	}
	var extraData []byte
	if v.ExtraData != "" {
		extraData, err = hex.DecodeString(v.ExtraData)
		if err != nil {
			return parityRecord{}, fmt.Errorf("decode extra_data: %w", err)
		}
	}

	att, err := attest.Parse(attestBytes)
	if err != nil {
		return parityRecord{}, fmt.Errorf("parse: %w", err)
	}

	rec := parityRecord{Name: v.Name}

	// TPM claims
	tpmResult, err := att.VerifyTPM(challenge, extraData)
	if err != nil {
		return parityRecord{}, fmt.Errorf("VerifyTPM: %w", err)
	}
	tpmClaims, err := tpmResult.ExtractTPMClaims(attest.ExtractOptions{PCRIndices: pcrIndices})
	if err != nil {
		return parityRecord{}, fmt.Errorf("ExtractTPMClaims: %w", err)
	}
	rec.TPMClaims = convertTPMClaims(tpmClaims)

	// TEE claims (skip for Shielded VM)
	if att.Platform() != attest.PlatformGCPShieldedVM {
		teeResult, err := att.VerifyBoundTEE(challenge, extraData)
		if err != nil {
			return parityRecord{}, fmt.Errorf("VerifyBoundTEE: %w", err)
		}
		teeClaims, err := teeResult.ExtractTEEClaims()
		if err != nil {
			return parityRecord{}, fmt.Errorf("ExtractTEEClaims: %w", err)
		}
		rec.TEEClaims = convertTEEClaims(teeClaims)
	}

	// Container claims (skip if no CEL)
	containerInfo, err := att.ExtractContainerClaims()
	if err == nil {
		rec.ContainerClaims = convertContainerClaims(containerInfo)
	}
	// If err != nil, leave ContainerClaims as nil (no CEL).

	return rec, nil
}

func convertTPMClaims(c *attest.TPMClaims) *parityTPM {
	pt := &parityTPM{
		Platform: c.Platform.PlatformTag(),
		Hardened: c.Hardened,
		PCRs:     make(map[string]string, len(c.PCRs)),
	}
	for idx, val := range c.PCRs {
		pt.PCRs[strconv.FormatUint(uint64(idx), 10)] = hex.EncodeToString(val[:])
	}
	if c.GCE != nil {
		pt.GCE = &parityGCE{
			ProjectID:     c.GCE.ProjectID,
			ProjectNumber: strconv.FormatUint(c.GCE.ProjectNumber, 10),
			Zone:          c.GCE.Zone,
			InstanceID:    strconv.FormatUint(c.GCE.InstanceID, 10),
			InstanceName:  c.GCE.InstanceName,
		}
	}
	return pt
}

func convertTEEClaims(c *attest.TEEClaims) *parityTEE {
	pt := &parityTEE{
		Platform: c.Platform.PlatformTag(),
	}
	if c.TDX != nil {
		pt.TDX = &parityTDX{
			MRTD:      hex.EncodeToString(c.TDX.MRTD[:]),
			RTMR0:     hex.EncodeToString(c.TDX.RTMR0[:]),
			RTMR1:     hex.EncodeToString(c.TDX.RTMR1[:]),
			RTMR2:     hex.EncodeToString(c.TDX.RTMR2[:]),
			RTMR3:     hex.EncodeToString(c.TDX.RTMR3[:]),
			TeeTcbSvn: hex.EncodeToString(c.TDX.TeeTcbSvn[:]),
			Attributes: parityTDAttrs{
				Debug:         c.TDX.Attributes.Debug,
				SeptVEDisable: c.TDX.Attributes.SeptVEDisable,
				PKS:           c.TDX.Attributes.PKS,
				KL:            c.TDX.Attributes.KL,
				PerfMon:       c.TDX.Attributes.PerfMon,
			},
		}
	}
	if c.SevSnp != nil {
		pt.SevSnp = &paritySevSnp{
			Measurement:  hex.EncodeToString(c.SevSnp.Measurement[:]),
			HostData:     hex.EncodeToString(c.SevSnp.HostData[:]),
			CurrentTcb:   strconv.FormatUint(c.SevSnp.CurrentTcb, 10),
			ReportedTcb:  strconv.FormatUint(c.SevSnp.ReportedTcb, 10),
			CommittedTcb: strconv.FormatUint(c.SevSnp.CommittedTcb, 10),
			GuestSvn:     c.SevSnp.GuestSvn,
			Policy: paritySevSnpPolicy{
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
	return pt
}

func convertContainerClaims(c *attest.ContainerInfo) *parityContainer {
	args := c.Args
	if args == nil {
		args = []string{}
	}
	envVars := c.EnvVars
	if envVars == nil {
		envVars = map[string]string{}
	}
	return &parityContainer{
		ImageReference: c.ImageReference,
		ImageDigest:    c.ImageDigest,
		ImageID:        c.ImageID,
		RestartPolicy:  c.RestartPolicy,
		Args:           args,
		EnvVars:        envVars,
	}
}
