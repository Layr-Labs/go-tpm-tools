package teeverify

import (
	"fmt"

	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
)

// Platform represents the CVM technology type.
type Platform int

const (
	PlatformUnknown       Platform = iota - 1 // -1
	PlatformIntelTDX                          // 0
	PlatformAMDSevSnp                         // 1
	PlatformGCPShieldedVM                     // 2, TPM-only, no TEE hardware attestation
)

// Platform tag constants for anti-downgrade protection in the TPM nonce.
const (
	PlatformTagIntelTDX      = "INTEL_TDX"
	PlatformTagAMDSevSnp     = "AMD_SEV_SNP"
	PlatformTagGCPShieldedVM = "GCP_SHIELDED_VM"
)

// PlatformTag returns the string tag used in TPM nonce computation.
func (p Platform) PlatformTag() string {
	switch p {
	case PlatformIntelTDX:
		return PlatformTagIntelTDX
	case PlatformAMDSevSnp:
		return PlatformTagAMDSevSnp
	case PlatformGCPShieldedVM:
		return PlatformTagGCPShieldedVM
	default:
		panic(fmt.Sprintf("unknown platform: %d", int(p)))
	}
}

// ExtractOptions configures claim extraction from a verified attestation.
type ExtractOptions struct {
	// PCRIndices specifies which PCR indices to extract from the vTPM quote.
	// Common PCRs:
	// - PCR 4: EFI boot applications (shim + GRUB)
	// - PCR 8: Kernel command line (includes dm-verity root hash)
	// - PCR 9: Files read by GRUB (kernel + initramfs)
	PCRIndices []uint32
}

// Attestation is a parsed attestation ready for verification.
// Use ParseAttestation to create, then call VerifyTPM and/or VerifyBoundTEE.
type Attestation struct {
	platform    Platform
	attestation *attestpb.Attestation
}

// Platform returns the detected platform.
func (a *Attestation) Platform() Platform {
	return a.platform
}

// VerifiedTPMAttestation is returned by VerifyTPM after successful TPM verification.
// Claims can only be extracted via ExtractClaims().
type VerifiedTPMAttestation struct {
	Platform     Platform
	ExtraData    []byte
	attestation  *attestpb.Attestation
	machineState *attestpb.MachineState
}

// VerifiedTEEAttestation is returned by VerifyBoundTEE after successful TEE verification.
// TEE claims can only be extracted via ExtractTEEClaims().
type VerifiedTEEAttestation struct {
	Platform    Platform
	ExtraData   []byte
	attestation *attestpb.Attestation
}

// TEEClaims contains TEE-specific claims (TDX or SEV-SNP only).
type TEEClaims struct {
	Platform Platform      `json:"platform"`
	TDX      *TDXClaims    `json:"tdx,omitempty"`
	SevSnp   *SevSnpClaims `json:"sevsnp,omitempty"`
}

// TPMClaims contains TPM-layer claims from a verified attestation.
// For TEE-specific claims (TDX/SEV-SNP), use VerifiedTEEAttestation.ExtractTEEClaims().
type TPMClaims struct {
	Platform  Platform       `json:"platform"`
	Hardened  bool           `json:"hardened"`
	Container *ContainerInfo `json:"container,omitempty"`
	GCE       *GCEInfo       `json:"gce,omitempty"`

	// PCRs contains the requested PCR values from the vTPM quote.
	// Keys are PCR indices (0-23), values are SHA-256 measurements (32 bytes).
	// Only PCRs specified in ExtractOptions.PCRIndices are included.
	PCRs map[uint32][32]byte `json:"pcrs"`
}

// TDXClaims contains Intel TDX-specific claims from the TD Quote.
// Zero values for byte arrays indicate the field was not present.
type TDXClaims struct {
	MRTD       [48]byte     `json:"mrtd"`        // Measurement of initial TD contents
	RTMR0      [48]byte     `json:"rtmr0"`       // Runtime measurement register 0
	RTMR1      [48]byte     `json:"rtmr1"`       // Runtime measurement register 1
	RTMR2      [48]byte     `json:"rtmr2"`       // Runtime measurement register 2
	RTMR3      [48]byte     `json:"rtmr3"`       // Runtime measurement register 3
	TeeTcbSvn  [16]byte     `json:"tee_tcb_svn"` // TEE TCB Security Version Number
	Attributes TDAttributes `json:"attributes"`
}

// TDAttributes contains TD attribute flags.
type TDAttributes struct {
	Debug         bool `json:"debug"`
	SeptVEDisable bool `json:"sept_ve_disable"`
	PKS           bool `json:"pks"`
	KL            bool `json:"kl"`
	PerfMon       bool `json:"perf_mon"`
}

// SevSnpClaims contains AMD SEV-SNP-specific claims from the attestation report.
// Zero values for byte arrays indicate the field was not present.
type SevSnpClaims struct {
	Measurement  [48]byte     `json:"measurement"`   // Guest measurement (launch digest)
	HostData     [32]byte     `json:"host_data"`     // Data provided by hypervisor at launch
	CurrentTcb   uint64       `json:"current_tcb"`   // Current TCB version
	ReportedTcb  uint64       `json:"reported_tcb"`  // TCB version when report was generated
	CommittedTcb uint64       `json:"committed_tcb"` // Committed TCB version
	GuestSvn     uint32       `json:"guest_svn"`     // Guest Security Version Number
	Policy       SevSnpPolicy `json:"policy"`
}

// SevSnpPolicy contains SEV-SNP guest policy flags.
type SevSnpPolicy struct {
	Debug                bool  `json:"debug"`
	MigrateMA            bool  `json:"migrate_ma"`
	SMT                  bool  `json:"smt"`
	ABIMinor             uint8 `json:"abi_minor"`
	ABIMajor             uint8 `json:"abi_major"`
	SingleSocket         bool  `json:"single_socket"`
	CipherTextHidingDRAM bool  `json:"ciphertext_hiding_dram"`
}

// ContainerInfo contains container claims.
type ContainerInfo struct {
	ImageReference string            `json:"image_reference"`
	ImageDigest    string            `json:"image_digest"`
	ImageID        string            `json:"image_id"`
	RestartPolicy  string            `json:"restart_policy"`
	Args           []string          `json:"args,omitempty"`
	EnvVars        map[string]string `json:"env_vars,omitempty"`
}

// GCEInfo contains GCE instance metadata.
type GCEInfo struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber uint64 `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceID    uint64 `json:"instance_id"`
	InstanceName  string `json:"instance_name"`
}
