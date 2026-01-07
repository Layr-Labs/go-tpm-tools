package rpverifier

import (
	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// Platform represents the CVM technology type.
type Platform int

const (
	PlatformUnknown Platform = iota
	PlatformTDX
	PlatformSevSnp
)

func (p Platform) String() string {
	switch p {
	case PlatformTDX:
		return "TDX"
	case PlatformSevSnp:
		return "SEV-SNP"
	default:
		return "Unknown"
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

// VerifiedAttestation wraps a cryptographically verified attestation.
// Claims can only be extracted from a verified attestation, ensuring
// callers cannot accidentally use unverified data.
type VerifiedAttestation struct {
	Platform     Platform
	attestation  *attestpb.Attestation
	machineState *attestpb.MachineState
}

// Claims contains all extracted claims from the attestation.
type Claims struct {
	Platform  Platform       `json:"platform"`
	Container *ContainerInfo `json:"container"`
	GCE       *GCEInfo       `json:"gce,omitempty"`
	TDX       *TDXClaims     `json:"tdx,omitempty"`
	SevSnp    *SevSnpClaims  `json:"sevsnp,omitempty"`

	// PCR values from vTPM (platform-agnostic, same for TDX and SEV-SNP)
	// Key is PCR index, value is SHA-256 measurement
	PCRs map[uint32][32]byte `json:"pcrs"`
}

// TDXClaims contains TDX-specific claims.
type TDXClaims struct {
	MRTD       [48]byte     `json:"mrtd"`
	RTMR0      [48]byte     `json:"rtmr0"`
	RTMR1      [48]byte     `json:"rtmr1"`
	RTMR2      [48]byte     `json:"rtmr2"`
	RTMR3      [48]byte     `json:"rtmr3"`
	TeeTcbSvn  [16]byte     `json:"tee_tcb_svn"`
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

// SevSnpClaims contains SEV-SNP-specific claims.
type SevSnpClaims struct {
	Measurement  [48]byte     `json:"measurement"`
	HostData     [32]byte     `json:"host_data"`
	CurrentTcb   uint64       `json:"current_tcb"`
	ReportedTcb  uint64       `json:"reported_tcb"`
	CommittedTcb uint64       `json:"committed_tcb"`
	GuestSvn     uint32       `json:"guest_svn"`
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
