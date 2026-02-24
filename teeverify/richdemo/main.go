// richdemo prints a human-readable breakdown of one attestation from each
// platform (Intel TDX, AMD SEV-SNP, GCP Shielded VM) from testdata/attestations.json.
//
// Run from the teeverify directory:
//
//	go run ./richdemo
package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	"github.com/Layr-Labs/go-tpm-tools/teeverify"
	"google.golang.org/protobuf/proto"
)

type vectorJSON struct {
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Hardened    bool   `json:"hardened"`
	Attestation string `json:"attestation"` // base64
	Challenge   string `json:"challenge"`   // hex
	ExtraData   string `json:"extra_data"`  // hex
}

func main() {
	data, err := os.ReadFile("testdata/attestations.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading attestations.json: %v\n", err)
		os.Exit(1)
	}

	var all []vectorJSON
	if err := json.Unmarshal(data, &all); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	// Pick the first vector of each platform.
	picked := map[string]vectorJSON{}
	for _, v := range all {
		if _, done := picked[v.Platform]; !done {
			picked[v.Platform] = v
		}
	}

	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════╗")
	fmt.Println("  ║          ATTESTATION RICH DEMO  ·  3 platforms       ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════╝")

	for _, platform := range []string{"intel_tdx", "amd_sev_snp", "gcp_shielded_vm"} {
		v, ok := picked[platform]
		if !ok {
			fmt.Printf("\n  [%s not found in test data]\n", platform)
			continue
		}
		if err := printAttestation(v); err != nil {
			fmt.Fprintf(os.Stderr, "\nerror processing %s: %v\n", v.Name, err)
		}
	}
}

func printAttestation(v vectorJSON) error {
	attestBytes, err := base64.StdEncoding.DecodeString(v.Attestation)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	challenge, err := hexDecode(v.Challenge)
	if err != nil {
		return fmt.Errorf("challenge decode: %w", err)
	}
	extraData, err := hexDecode(v.ExtraData)
	if err != nil {
		return fmt.Errorf("extra_data decode: %w", err)
	}

	attest, err := teeverify.ParseAttestation(attestBytes)
	if err != nil {
		return fmt.Errorf("ParseAttestation: %w", err)
	}

	allPCRs := make([]uint32, 24)
	for i := range allPCRs {
		allPCRs[i] = uint32(i)
	}

	verifiedTPM, err := attest.VerifyTPM(challenge, extraData)
	if err != nil {
		return fmt.Errorf("VerifyTPM: %w", err)
	}
	tpmClaims, err := verifiedTPM.ExtractTPMClaims(teeverify.ExtractOptions{PCRIndices: allPCRs})
	if err != nil {
		return fmt.Errorf("ExtractTPMClaims: %w", err)
	}

	container, err := attest.ExtractContainerClaims()
	if err != nil {
		return fmt.Errorf("ExtractContainerClaims: %w", err)
	}

	// TEE claims are only available for TDX and SEV-SNP.
	var teeClaims *teeverify.TEEClaims
	if v.Platform == "intel_tdx" || v.Platform == "amd_sev_snp" {
		verifiedTEE, err := attest.VerifyBoundTEE(challenge, extraData)
		if err != nil {
			return fmt.Errorf("VerifyBoundTEE: %w", err)
		}
		teeClaims, err = verifiedTEE.ExtractTEEClaims()
		if err != nil {
			return fmt.Errorf("ExtractTEEClaims: %w", err)
		}
	}

	// Parse raw proto only for the AK cert validity window.
	var rawAttest attestpb.Attestation
	proto.Unmarshal(attestBytes, &rawAttest)

	fmt.Println()
	fmt.Println("  ────────────────────────────────────────────────────────")
	fmt.Printf("  %s\n", v.Name)
	fmt.Println("  ────────────────────────────────────────────────────────")

	printBasic(v.Platform, &rawAttest, tpmClaims, container, teeClaims)
	printAdvanced(tpmClaims, teeClaims)
	return nil
}

func printBasic(platform string, raw *attestpb.Attestation, tpm *teeverify.TPMClaims, container *teeverify.ContainerInfo, tee *teeverify.TEEClaims) {
	fmt.Println()
	fmt.Println("  BASIC")

	labels := map[string]string{
		"intel_tdx":       "Intel TDX",
		"amd_sev_snp":     "AMD SEV-SNP",
		"gcp_shielded_vm": "GCP Shielded VM",
	}
	fmt.Printf("    Platform:  %s\n", labels[platform])

	mode := "debug"
	if tpm.Hardened {
		mode = "hardened"
	}
	fmt.Printf("    Mode:      %s\n", mode)

	if cert := raw.GetAkCert(); len(cert) > 0 {
		if parsed, err := x509.ParseCertificate(cert); err == nil {
			fmt.Printf("    AK Cert:   valid %s → %s\n",
				parsed.NotBefore.Format("2006-01-02"),
				parsed.NotAfter.Format("2006-01-02"))
		}
	}

	fmt.Println()
	if gce := tpm.GCE; gce != nil {
		fmt.Println("    GCE Instance")
		fmt.Printf("      Project:   %s  (#%d)\n", gce.ProjectID, gce.ProjectNumber)
		fmt.Printf("      Zone:      %s\n", gce.Zone)
		fmt.Printf("      Instance:  %s  (id: %d)\n", gce.InstanceName, gce.InstanceID)
	} else {
		fmt.Println("    GCE Instance")
		fmt.Println("      (not present in this vector)")
	}

	fmt.Println()
	if c := container; c != nil {
		fmt.Println("    Container")
		fmt.Printf("      Image:     %s\n", c.ImageReference)
		fmt.Printf("      Digest:    %s\n", c.ImageDigest)
		fmt.Printf("      Restart:   %s\n", c.RestartPolicy)
		if len(c.Args) > 0 {
			fmt.Printf("      Args:      %s\n", strings.Join(c.Args, " "))
		}
		if len(c.EnvVars) > 0 {
			keys := make([]string, 0, len(c.EnvVars))
			for k := range c.EnvVars {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Printf("      Env:       %s=%s\n", keys[0], c.EnvVars[keys[0]])
			for _, k := range keys[1:] {
				fmt.Printf("                 %s=%s\n", k, c.EnvVars[k])
			}
		}
	} else {
		fmt.Println("    Container")
		fmt.Println("      (not present in this vector)")
	}

	// TEE key measurement — one line summary.
	fmt.Println()
	if tee != nil {
		if tdx := tee.TDX; tdx != nil {
			fmt.Println("    TEE Measurement")
			fmt.Printf("      MRTD:  %s\n", hex.EncodeToString(tdx.MRTD[:]))
		} else if snp := tee.SevSnp; snp != nil {
			fmt.Println("    TEE Measurement")
			fmt.Printf("      Measurement:  %s\n", hex.EncodeToString(snp.Measurement[:]))
		}
	} else {
		fmt.Println("    TEE Measurement")
		fmt.Println("      (none — Shielded VM is TPM-only)")
	}
}

func printAdvanced(tpm *teeverify.TPMClaims, tee *teeverify.TEEClaims) {
	fmt.Println()
	fmt.Println("  ADVANCED")

	// PCRs from verified TPM claims.
	if len(tpm.PCRs) > 0 {
		indices := make([]int, 0, len(tpm.PCRs))
		for idx := range tpm.PCRs {
			indices = append(indices, int(idx))
		}
		sort.Ints(indices)
		fmt.Println()
		fmt.Println("    PCRs (SHA-256)")
		for _, idx := range indices {
			val := tpm.PCRs[uint32(idx)]
			fmt.Printf("      PCR %2d:  %s\n", idx, hex.EncodeToString(val[:]))
		}
	}

	if tee == nil {
		return
	}

	if tdx := tee.TDX; tdx != nil {
		fmt.Println()
		fmt.Println("    TDX Measurements")
		fmt.Printf("      MRTD:       %s\n", hex.EncodeToString(tdx.MRTD[:]))
		fmt.Printf("      RTMR0:      %s\n", hex.EncodeToString(tdx.RTMR0[:]))
		fmt.Printf("      RTMR1:      %s\n", hex.EncodeToString(tdx.RTMR1[:]))
		fmt.Printf("      RTMR2:      %s\n", hex.EncodeToString(tdx.RTMR2[:]))
		fmt.Printf("      RTMR3:      %s\n", hex.EncodeToString(tdx.RTMR3[:]))
		fmt.Printf("      TeeTcbSvn:  %s\n", hex.EncodeToString(tdx.TeeTcbSvn[:]))

		fmt.Println()
		fmt.Println("    TD Attributes")
		fmt.Printf("      Debug:         %v\n", tdx.Attributes.Debug)
		fmt.Printf("      SeptVEDisable: %v\n", tdx.Attributes.SeptVEDisable)
		fmt.Printf("      PKS:           %v\n", tdx.Attributes.PKS)
		fmt.Printf("      KL:            %v\n", tdx.Attributes.KL)
		fmt.Printf("      PerfMon:       %v\n", tdx.Attributes.PerfMon)
	}

	if snp := tee.SevSnp; snp != nil {
		fmt.Println()
		fmt.Println("    SEV-SNP Measurements")
		fmt.Printf("      Measurement:   %s\n", hex.EncodeToString(snp.Measurement[:]))
		fmt.Printf("      HostData:      %s\n", hex.EncodeToString(snp.HostData[:]))
		fmt.Printf("      GuestSvn:      %d\n", snp.GuestSvn)
		fmt.Printf("      CurrentTcb:    0x%016x\n", snp.CurrentTcb)
		fmt.Printf("      ReportedTcb:   0x%016x\n", snp.ReportedTcb)
		fmt.Printf("      CommittedTcb:  0x%016x\n", snp.CommittedTcb)

		p := snp.Policy
		fmt.Println()
		fmt.Println("    SEV-SNP Policy")
		fmt.Printf("      Debug:                %v\n", p.Debug)
		fmt.Printf("      MigrateMA:            %v\n", p.MigrateMA)
		fmt.Printf("      SMT:                  %v\n", p.SMT)
		fmt.Printf("      ABIMinor:             %d\n", p.ABIMinor)
		fmt.Printf("      ABIMajor:             %d\n", p.ABIMajor)
		fmt.Printf("      SingleSocket:         %v\n", p.SingleSocket)
		fmt.Printf("      CipherTextHidingDRAM: %v\n", p.CipherTextHidingDRAM)
	}
}

func hexDecode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}
