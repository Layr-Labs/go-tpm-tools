// Package main provides policy checking for CVM attestations.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/google/go-tpm-tools/research/verifier"
)

// PolicyChecker enforces attestation policies against on-chain allowlists
// and Google's firmware endorsements.
type PolicyChecker struct {
	firmware *FirmwareVerifier
	contract *BaseImageAllowlist
}

// NewPolicyChecker creates a new policy checker.
func NewPolicyChecker(fw *FirmwareVerifier, contract *BaseImageAllowlist) *PolicyChecker {
	return &PolicyChecker{
		firmware: fw,
		contract: contract,
	}
}

// Check verifies that the claims meet policy requirements.
func (p *PolicyChecker) Check(ctx context.Context, claims *verifier.Claims) error {
	switch claims.Platform {
	case verifier.PlatformTDX:
		return p.checkTDX(ctx, claims)
	case verifier.PlatformSevSnp:
		return p.checkSevSnp(ctx, claims)
	default:
		return fmt.Errorf("unknown platform: %d", claims.Platform)
	}
}

func (p *PolicyChecker) checkTDX(ctx context.Context, claims *verifier.Claims) error {
	if claims.TDX == nil {
		return fmt.Errorf("no TDX claims")
	}

	// Require Secure Boot
	if claims.TDX.Firmware != nil && !claims.TDX.Firmware.SecureBootEnabled {
		return fmt.Errorf("Secure Boot must be enabled")
	}

	// Verify MRTD against Google's firmware endorsements
	log.Printf("  MRTD: %x", claims.TDX.MRTD)
	endorsement, err := p.firmware.VerifyMRTD(ctx, claims.TDX.MRTD[:])
	if err != nil {
		return fmt.Errorf("firmware not endorsed by Google: %w", err)
	}
	log.Printf("  Firmware endorsed: SVN=%d", endorsement.SVN)

	// Check TCB version against on-chain allowlist
	major := uint64(claims.TDX.TeeTcbSvn[1])
	minor := uint64(claims.TDX.TeeTcbSvn[0])
	microcode := uint64(claims.TDX.TeeTcbSvn[2])
	tcbPacked := major<<16 | minor<<8 | microcode
	tcbAllowed, err := p.contract.CheckTcb(&bind.CallOpts{Context: ctx}, 0, tcbPacked)
	if err != nil {
		return fmt.Errorf("failed to check TCB: %w", err)
	}
	if !tcbAllowed {
		return fmt.Errorf("TCB version does not meet minimum requirement")
	}

	// Check base image allowlist using grub.cfg digest
	if claims.TDX.GrubCfgDigest == nil {
		return fmt.Errorf("missing CCEL data - cannot verify base image")
	}
	imageAllowed, err := p.contract.IsImageAllowed(&bind.CallOpts{Context: ctx}, 0, claims.TDX.GrubCfgDigest)
	if err != nil {
		return fmt.Errorf("failed to check image: %w", err)
	}
	if !imageAllowed {
		log.Printf("  GrubCfg not in allowlist: %x", claims.TDX.GrubCfgDigest)
		return fmt.Errorf("base image not in allowlist")
	}

	return nil
}

func (p *PolicyChecker) checkSevSnp(ctx context.Context, claims *verifier.Claims) error {
	if claims.SevSnp == nil {
		return fmt.Errorf("no SEV-SNP claims")
	}

	// Verify firmware measurement against Google's endorsements
	log.Printf("  MEASUREMENT: %x", claims.SevSnp.Measurement)
	endorsement, err := p.firmware.VerifySevSnpMeasurement(ctx, claims.SevSnp.Measurement[:])
	if err != nil {
		return fmt.Errorf("firmware not endorsed by Google: %w", err)
	}
	log.Printf("  Firmware endorsed: SVN=%d", endorsement.SVN)

	// Check TCB version against on-chain allowlist
	tcbAllowed, err := p.contract.CheckTcb(&bind.CallOpts{Context: ctx}, 1, claims.SevSnp.CurrentTcb)
	if err != nil {
		return fmt.Errorf("failed to check TCB: %w", err)
	}
	if !tcbAllowed {
		return fmt.Errorf("TCB version does not meet minimum requirement")
	}

	// Check base image allowlist using grub.cfg digest
	if claims.SevSnp.GrubCfgDigest == nil {
		return fmt.Errorf("missing grub.cfg digest - cannot verify base image")
	}
	imageAllowed, err := p.contract.IsImageAllowed(&bind.CallOpts{Context: ctx}, 1, claims.SevSnp.GrubCfgDigest)
	if err != nil {
		return fmt.Errorf("failed to check image: %w", err)
	}
	if !imageAllowed {
		log.Printf("  GrubCfg not in allowlist: %x", claims.SevSnp.GrubCfgDigest)
		return fmt.Errorf("base image not in allowlist")
	}

	return nil
}
