package rpverifier

import (
	"fmt"

	sabi "github.com/google/go-sev-guest/abi"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
)

// ExtractClaims extracts claims from a verified attestation.
func (v *VerifiedAttestation) ExtractClaims(opts ExtractOptions) (*Claims, error) {
	claims := &Claims{Platform: v.Platform}

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

	if cos := v.machineState.GetCos(); cos != nil {
		if c := cos.GetContainer(); c != nil {
			claims.Container = &ContainerInfo{
				ImageReference: c.GetImageReference(),
				ImageDigest:    c.GetImageDigest(),
				ImageID:        c.GetImageId(),
				RestartPolicy:  c.GetRestartPolicy().String(),
				Args:           c.GetArgs(),
				EnvVars:        c.GetEnvVars(),
			}
		}
	}

	switch v.Platform {
	case PlatformTDX:
		tdxClaims, err := extractTDXClaims(v.attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to extract TDX claims: %w", err)
		}
		claims.TDX = tdxClaims
	case PlatformSevSnp:
		sevClaims, err := extractSevSnpClaims(v.attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to extract SEV-SNP claims: %w", err)
		}
		claims.SevSnp = sevClaims
	}

	return claims, nil
}

func extractPCRs(attestation *attestpb.Attestation, indices []uint32) (map[uint32][32]byte, error) {
	result := make(map[uint32][32]byte)

	var sha256PCRs *tpmpb.PCRs
	for _, quote := range attestation.GetQuotes() {
		if quote.GetPcrs().GetHash() == tpmpb.HashAlgo_SHA256 {
			sha256PCRs = quote.GetPcrs()
			break
		}
	}

	if sha256PCRs == nil {
		return nil, fmt.Errorf("no SHA-256 PCR bank found in attestation")
	}

	pcrs := sha256PCRs.GetPcrs()

	for _, idx := range indices {
		val, ok := pcrs[idx]
		if !ok || len(val) != 32 {
			return nil, fmt.Errorf("PCR %d not found or invalid length", idx)
		}
		var pcrVal [32]byte
		copy(pcrVal[:], val)
		result[idx] = pcrVal
	}

	return result, nil
}

func extractTDXClaims(attestation *attestpb.Attestation) (*TDXClaims, error) {
	quote := attestation.GetTdxAttestation()

	tdAttrs := quote.GetTdQuoteBody().GetTdAttributes()
	if len(tdAttrs) < 2 {
		return nil, fmt.Errorf("TD attributes too short")
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

	if tcb := quote.GetTdQuoteBody().GetTeeTcbSvn(); len(tcb) >= 16 {
		copy(claims.TeeTcbSvn[:], tcb[:16])
	}

	if mrtd := quote.GetTdQuoteBody().GetMrTd(); len(mrtd) >= 48 {
		copy(claims.MRTD[:], mrtd[:48])
	}

	if rtmrs := quote.GetTdQuoteBody().GetRtmrs(); len(rtmrs) >= 4 {
		if len(rtmrs[0]) >= 48 {
			copy(claims.RTMR0[:], rtmrs[0][:48])
		}
		if len(rtmrs[1]) >= 48 {
			copy(claims.RTMR1[:], rtmrs[1][:48])
		}
		if len(rtmrs[2]) >= 48 {
			copy(claims.RTMR2[:], rtmrs[2][:48])
		}
		if len(rtmrs[3]) >= 48 {
			copy(claims.RTMR3[:], rtmrs[3][:48])
		}
	}

	return claims, nil
}

func extractSevSnpClaims(attestation *attestpb.Attestation) (*SevSnpClaims, error) {
	snpAttestation := attestation.GetSevSnpAttestation()
	report := snpAttestation.GetReport()

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

	if m := report.GetMeasurement(); len(m) >= 48 {
		copy(claims.Measurement[:], m[:48])
	}
	if h := report.GetHostData(); len(h) >= 32 {
		copy(claims.HostData[:], h[:32])
	}

	return claims, nil
}
