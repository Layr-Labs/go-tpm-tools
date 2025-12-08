// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseImageAllowlist
/// @notice Allowlist for custom TDX base images with support level tracking
/// @dev Two validation layers:
///      1. Minimum SVN - reject outdated platform TCBs
///      2. RTMR1 support levels - custom image versioning (LATEST/STABLE/USABLE/EXPERIMENTAL)
///
///      Note: MRTD (firmware) validation is handled off-chain by verifying Google's
///      signed endorsements from gs://gce_tcb_integrity/ovmf_x64_csm/tdx/
contract BaseImageAllowlist {
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

    // SVN: minimum platform TCB version
    uint32 public minimumSVN;

    // RTMR1: custom image support levels
    SupportLevel public minimumSupportLevel;
    mapping(bytes32 => SupportLevel) public imageSupport;

    event MinimumSVNUpdated(uint32 oldSVN, uint32 newSVN);
    event ImageSupportUpdated(bytes32 indexed rtmr1, SupportLevel level);
    event MinimumSupportLevelUpdated(SupportLevel oldLevel, SupportLevel newLevel);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NOT_OWNER();
    error ZERO_ADDRESS();

    modifier onlyOwner() {
        require(msg.sender == owner, NOT_OWNER());
        _;
    }

    constructor() {
        owner = msg.sender;
        minimumSupportLevel = SupportLevel.STABLE;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ============ SVN Functions ============

    /// @notice Update the minimum SVN requirement
    /// @param newSVN The new minimum SVN
    function setMinimumSVN(uint32 newSVN) external onlyOwner {
        uint32 oldSVN = minimumSVN;
        minimumSVN = newSVN;
        emit MinimumSVNUpdated(oldSVN, newSVN);
    }

    /// @notice Check if an SVN meets the minimum requirement
    /// @param svn The SVN to check
    /// @return True if the SVN meets the minimum
    function checkSVN(uint32 svn) external view returns (bool) {
        return svn >= minimumSVN;
    }

    // ============ RTMR1 Support Level Functions ============

    /// @notice Set the support level for an image
    /// @param rtmr1 RTMR[1] - custom image measurement (kernel, initrd)
    /// @param level The support level for this image
    function setImageSupport(bytes calldata rtmr1, SupportLevel level) external onlyOwner {
        bytes32 key = keccak256(rtmr1);
        imageSupport[key] = level;
        emit ImageSupportUpdated(key, level);
    }

    /// @notice Remove an image from the allowlist (sets to NONE)
    /// @param rtmr1 RTMR[1] - custom image measurement
    function removeImage(bytes calldata rtmr1) external onlyOwner {
        bytes32 key = keccak256(rtmr1);
        imageSupport[key] = SupportLevel.NONE;
        emit ImageSupportUpdated(key, SupportLevel.NONE);
    }

    /// @notice Update the minimum support level requirement
    /// @param newLevel The new minimum support level
    function setMinimumSupportLevel(SupportLevel newLevel) external onlyOwner {
        SupportLevel oldLevel = minimumSupportLevel;
        minimumSupportLevel = newLevel;
        emit MinimumSupportLevelUpdated(oldLevel, newLevel);
    }

    /// @notice Check if an image meets the minimum support level
    /// @param rtmr1 RTMR[1] - custom image measurement
    /// @return True if the image meets the minimum support level
    function isImageAllowed(bytes calldata rtmr1) external view returns (bool) {
        bytes32 key = keccak256(rtmr1);
        return checkSupport(imageSupport[key], minimumSupportLevel);
    }

    /// @notice Get the support level for an image
    /// @param rtmr1 RTMR[1] - custom image measurement
    /// @return The support level
    function getImageSupport(bytes calldata rtmr1) external view returns (SupportLevel) {
        bytes32 key = keccak256(rtmr1);
        return imageSupport[key];
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
