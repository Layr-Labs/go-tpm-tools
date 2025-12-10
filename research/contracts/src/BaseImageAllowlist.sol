// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseImageAllowlist
/// @notice Allowlist for custom CVM base images with support level tracking
/// @dev Two validation layers:
///      1. Minimum TCB - reject outdated platform TCBs (per-CVM)
///      2. Base image support levels - custom image versioning
///         - TDX: grub.cfg digest (48 bytes SHA384, extracted from CCEL)
///         - SEV-SNP: grub.cfg digest (extracted from TPM event log)
contract BaseImageAllowlist {
    /// @notice Supported Confidential VM technologies
    enum CVM {
        TDX,      // 0 - Intel Trust Domain Extensions
        SEV_SNP   // 1 - AMD Secure Encrypted Virtualization - Secure Nested Paging
    }

    /// @notice Support level for an image, mirrors Google's Confidential Space attributes
    /// @dev EXPERIMENTAL is outside the normal hierarchy - it only passes if minimum is also EXPERIMENTAL
    enum SupportLevel {
        NONE,           // 0 - not in allowlist
        EXPERIMENTAL,   // 1 - preview/testing only, never production
        USABLE,         // 2 - out of support, use at own risk
        STABLE,         // 3 - supported, monitored for vulns
        LATEST          // 4 - latest version, also stable and usable
    }

    address public owner;

    /// @notice Minimum TCB version per CVM platform
    /// @dev TDX: Pack TeeTcbSvn[0:3] as (major << 16 | minor << 8 | microcode)
    ///      SEV-SNP: Use CurrentTcb directly (uint64 with packed component versions)
    mapping(CVM => uint64) public minimumTcb;

    // Base image support levels (grub.cfg digest for both TDX and SEV-SNP)
    SupportLevel public minimumSupportLevel;
    mapping(CVM => mapping(bytes32 => SupportLevel)) public imageSupport;

    event MinimumTcbUpdated(CVM indexed cvm, uint64 oldTcb, uint64 newTcb);
    event ImageSupportUpdated(CVM indexed cvm, bytes32 indexed measurementHash, SupportLevel level);
    event MinimumSupportLevelUpdated(SupportLevel oldLevel, SupportLevel newLevel);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NOT_OWNER();
    error ZERO_ADDRESS();
    error INVALID_CVM();

    modifier onlyOwner() {
        require(msg.sender == owner, NOT_OWNER());
        _;
    }

    constructor() {
        owner = msg.sender;
        minimumSupportLevel = SupportLevel.STABLE;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ============ TCB Functions ============

    /// @notice Update the minimum TCB requirement for a CVM platform
    /// @param cvm The CVM platform (TDX or SEV_SNP)
    /// @param newTcb The new minimum TCB version
    /// @dev For TDX: pack TeeTcbSvn bytes as (major << 16 | minor << 8 | microcode)
    ///      For SEV-SNP: use CurrentTcb directly from the attestation report
    function setMinimumTcb(CVM cvm, uint64 newTcb) external onlyOwner {
        uint64 oldTcb = minimumTcb[cvm];
        minimumTcb[cvm] = newTcb;
        emit MinimumTcbUpdated(cvm, oldTcb, newTcb);
    }

    /// @notice Check if a TCB version meets the minimum requirement for a CVM platform
    /// @param cvm The CVM platform (TDX or SEV_SNP)
    /// @param tcb The TCB version to check
    /// @return True if the TCB meets the minimum
    function checkTcb(CVM cvm, uint64 tcb) external view returns (bool) {
        return tcb >= minimumTcb[cvm];
    }

    // ============ Base Image Support Level Functions ============

    /// @notice Set the support level for a base image measurement
    /// @param cvm The CVM platform (grub.cfg digest for both TDX and SEV_SNP)
    /// @param measurement The measurement bytes (48 bytes SHA384 for TDX, 32 bytes SHA256 for SEV-SNP)
    /// @param level The support level for this image
    function setImageSupport(CVM cvm, bytes calldata measurement, SupportLevel level) external onlyOwner {
        bytes32 key = keccak256(measurement);
        imageSupport[cvm][key] = level;
        emit ImageSupportUpdated(cvm, key, level);
    }

    /// @notice Remove an image from the allowlist (sets to NONE)
    /// @param cvm The CVM platform
    /// @param measurement The measurement bytes
    function removeImage(CVM cvm, bytes calldata measurement) external onlyOwner {
        bytes32 key = keccak256(measurement);
        imageSupport[cvm][key] = SupportLevel.NONE;
        emit ImageSupportUpdated(cvm, key, SupportLevel.NONE);
    }

    /// @notice Update the minimum support level requirement
    /// @param newLevel The new minimum support level
    function setMinimumSupportLevel(SupportLevel newLevel) external onlyOwner {
        SupportLevel oldLevel = minimumSupportLevel;
        minimumSupportLevel = newLevel;
        emit MinimumSupportLevelUpdated(oldLevel, newLevel);
    }

    /// @notice Check if an image meets the minimum support level
    /// @param cvm The CVM platform
    /// @param measurement The measurement bytes
    /// @return True if the image meets the minimum support level
    function isImageAllowed(CVM cvm, bytes calldata measurement) external view returns (bool) {
        bytes32 key = keccak256(measurement);
        return checkSupport(imageSupport[cvm][key], minimumSupportLevel);
    }

    /// @notice Get the support level for an image
    /// @param cvm The CVM platform
    /// @param measurement The measurement bytes
    /// @return The support level
    function getImageSupport(CVM cvm, bytes calldata measurement) external view returns (SupportLevel) {
        bytes32 key = keccak256(measurement);
        return imageSupport[cvm][key];
    }

    /// @notice Check if an image level meets a minimum requirement
    /// @dev EXPERIMENTAL only passes if minimum is also EXPERIMENTAL
    /// @param level The image's support level
    /// @param minimum The minimum required level
    /// @return True if level meets minimum
    function checkSupport(SupportLevel level, SupportLevel minimum) public pure returns (bool) {
        if (level == SupportLevel.NONE) {
            return false;
        }
        if (level == SupportLevel.EXPERIMENTAL) {
            return minimum == SupportLevel.EXPERIMENTAL;
        }
        return level >= minimum;
    }

    // ============ Ownership ============

    /// @notice Transfer ownership to a new address
    /// @param newOwner The new owner address
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), ZERO_ADDRESS());
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
