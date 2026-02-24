package teeverify

import (
	"fmt"
	"slices"
	"strings"

	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	tpmpb "github.com/Layr-Labs/go-tpm-tools/proto/tpm"
	sabi "github.com/google/go-sev-guest/abi"
)

// ExtractTPMClaims extracts TPM-layer claims from a verified TPM attestation.
// This includes PCRs, GCE metadata, and hardened status.
// For TEE-specific claims, use VerifiedTEEAttestation.ExtractTEEClaims().
// For container claims, use Attestation.ExtractContainerClaims().
func (v *VerifiedTPMAttestation) ExtractTPMClaims(opts ExtractOptions) (*TPMClaims, error) {
	claims := &TPMClaims{
		Platform: v.Platform,
		Hardened: isHardened(v.machineState.GetLinuxKernel().GetCommandLine()),
	}

	pcrs, err := extractPCRs(v.attestation, opts.PCRIndices)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PCRs: %w", err)
	}
	claims.PCRs = pcrs

	if p := v.machineState.GetPlatform(); p != nil {
		if info := p.GetInstanceInfo(); info != nil {
			claims.GCE = &GCEInfo{
				ProjectID:     info.GetProjectId(),
				ProjectNumber: info.GetProjectNumber(),
				Zone:          info.GetZone(),
				InstanceID:    info.GetInstanceId(),
				InstanceName:  info.GetInstanceName(),
			}
		}
	}

	return claims, nil
}

// ExtractTEEClaims extracts TEE-specific claims (TDX or SEV-SNP) from a verified TEE attestation.
func (v *VerifiedTEEAttestation) ExtractTEEClaims() (*TEEClaims, error) {
	claims := &TEEClaims{
		Platform: v.Platform,
	}

	switch v.Platform {
	case PlatformIntelTDX:
		tdxClaims, err := extractTDXClaims(v.attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to extract TDX claims: %w", err)
		}
		claims.TDX = tdxClaims
	case PlatformAMDSevSnp:
		sevClaims, err := extractSevSnpClaims(v.attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to extract SEV-SNP claims: %w", err)
		}
		claims.SevSnp = sevClaims
	default:
		return nil, fmt.Errorf("no TEE claims available for platform %s", v.Platform.PlatformTag())
	}

	return claims, nil
}

func extractPCRs(attestation *attestpb.Attestation, indices []uint32) (map[uint32][32]byte, error) {
	// Validate PCR indices (TPM 2.0 has PCRs 0-23)
	for _, idx := range indices {
		if idx > 23 {
			return nil, fmt.Errorf("invalid PCR index %d (must be 0-23)", idx)
		}
	}

	var sha256PCRs map[uint32][]byte
	for _, quote := range attestation.GetQuotes() {
		if quote.GetPcrs().GetHash() == tpmpb.HashAlgo_SHA256 {
			sha256PCRs = quote.GetPcrs().GetPcrs()
			break
		}
	}
	if sha256PCRs == nil {
		return nil, fmt.Errorf("attestation contains no SHA-256 PCR quotes")
	}

	result := make(map[uint32][32]byte, len(indices))
	for _, idx := range indices {
		val, ok := sha256PCRs[idx]
		if !ok {
			return nil, fmt.Errorf("PCR %d not found in attestation", idx)
		}
		if len(val) != 32 {
			return nil, fmt.Errorf("PCR %d has invalid length: got %d, expected 32", idx, len(val))
		}
		var pcrVal [32]byte
		copy(pcrVal[:], val)
		result[idx] = pcrVal
	}

	return result, nil
}

func extractTDXClaims(attestation *attestpb.Attestation) (*TDXClaims, error) {
	quote := attestation.GetTdxAttestation()
	if quote == nil {
		return nil, fmt.Errorf("TDX attestation is nil")
	}

	quoteBody := quote.GetTdQuoteBody()
	if quoteBody == nil {
		return nil, fmt.Errorf("TDX quote body is nil")
	}

	tdAttrs := quoteBody.GetTdAttributes()
	if len(tdAttrs) < 2 {
		return nil, fmt.Errorf("TD attributes too short: got %d bytes, need at least 2", len(tdAttrs))
	}

	claims := &TDXClaims{
		Attributes: TDAttributes{
			Debug:         tdAttrs[0]&0x01 != 0,
			SeptVEDisable: tdAttrs[0]&0x10 != 0,
			PKS:           tdAttrs[0]&0x40 != 0,
			KL:            tdAttrs[0]&0x80 != 0,
			PerfMon:       tdAttrs[1]&0x01 != 0,
		},
	}

	// Extract TEE TCB SVN (must be exactly 16 bytes if present)
	if tcb := quoteBody.GetTeeTcbSvn(); len(tcb) > 0 {
		if len(tcb) != 16 {
			return nil, fmt.Errorf("invalid TeeTcbSvn length: got %d, expected 16", len(tcb))
		}
		copy(claims.TeeTcbSvn[:], tcb)
	}

	// Extract MRTD (must be exactly 48 bytes if present)
	if mrtd := quoteBody.GetMrTd(); len(mrtd) > 0 {
		if len(mrtd) != 48 {
			return nil, fmt.Errorf("invalid MRTD length: got %d, expected 48", len(mrtd))
		}
		copy(claims.MRTD[:], mrtd)
	}

	// Extract RTMRs (each must be exactly 48 bytes if present)
	if rtmrs := quoteBody.GetRtmrs(); len(rtmrs) > 0 {
		if len(rtmrs) != 4 {
			return nil, fmt.Errorf("invalid RTMR count: got %d, expected 4", len(rtmrs))
		}
		for i, rtmr := range rtmrs {
			if len(rtmr) != 48 {
				return nil, fmt.Errorf("invalid RTMR%d length: got %d, expected 48", i, len(rtmr))
			}
		}
		copy(claims.RTMR0[:], rtmrs[0])
		copy(claims.RTMR1[:], rtmrs[1])
		copy(claims.RTMR2[:], rtmrs[2])
		copy(claims.RTMR3[:], rtmrs[3])
	}

	return claims, nil
}

func extractSevSnpClaims(attestation *attestpb.Attestation) (*SevSnpClaims, error) {
	snpAttestation := attestation.GetSevSnpAttestation()
	if snpAttestation == nil {
		return nil, fmt.Errorf("SEV-SNP attestation is nil")
	}

	report := snpAttestation.GetReport()
	if report == nil {
		return nil, fmt.Errorf("SEV-SNP report is nil")
	}

	guestPolicy, err := sabi.ParseSnpPolicy(report.GetPolicy())
	if err != nil {
		return nil, fmt.Errorf("failed to parse guest policy: %w", err)
	}

	claims := &SevSnpClaims{
		CurrentTcb:   report.GetCurrentTcb(),
		ReportedTcb:  report.GetReportedTcb(),
		CommittedTcb: report.GetCommittedTcb(),
		GuestSvn:     report.GetGuestSvn(),
		Policy: SevSnpPolicy{
			Debug:                guestPolicy.Debug,
			MigrateMA:            guestPolicy.MigrateMA,
			SMT:                  guestPolicy.SMT,
			ABIMinor:             guestPolicy.ABIMinor,
			ABIMajor:             guestPolicy.ABIMajor,
			SingleSocket:         guestPolicy.SingleSocket,
			CipherTextHidingDRAM: guestPolicy.CipherTextHidingDRAM,
		},
	}

	// Extract Measurement (must be exactly 48 bytes if present)
	if m := report.GetMeasurement(); len(m) > 0 {
		if len(m) != 48 {
			return nil, fmt.Errorf("invalid Measurement length: got %d, expected 48", len(m))
		}
		copy(claims.Measurement[:], m)
	}

	// Extract HostData (must be exactly 32 bytes if present)
	if h := report.GetHostData(); len(h) > 0 {
		if len(h) != 32 {
			return nil, fmt.Errorf("invalid HostData length: got %d, expected 32", len(h))
		}
		copy(claims.HostData[:], h)
	}

	return claims, nil
}

func isHardened(cmdline string) bool {
	return slices.Contains(strings.Fields(cmdline), "confidential-space.hardened=true")
}
