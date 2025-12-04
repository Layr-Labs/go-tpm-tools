// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseImageAllowlist
/// @notice Allowlist for TDX measurements with support level tracking
/// @dev Three validation layers:
///      1. Minimum SVN - reject outdated platform TCBs
///      2. MRTD allowlist - golden firmware measurements (from Google endorsements)
///      3. RTMR1 support levels - custom image versioning (LATEST/STABLE/USABLE/EXPERIMENTAL)
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

    // MRTD: golden firmware measurements from Google endorsements
    mapping(bytes32 => bool) public allowedMRTD;

    // RTMR1: custom image support levels
    SupportLevel public minimumSupportLevel;
    mapping(bytes32 => SupportLevel) public imageSupport;

    event MRTDAdded(bytes indexed mrtd);
    event MRTDRemoved(bytes indexed mrtd);
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

    // ============ MRTD Functions ============

    /// @notice Add an MRTD to the allowlist (from Google endorsements)
    /// @param mrtd The MRTD measurement (48 bytes)
    function addMRTD(bytes calldata mrtd) external onlyOwner {
        bytes32 key = keccak256(mrtd);
        allowedMRTD[key] = true;
        emit MRTDAdded(mrtd);
    }

    /// @notice Remove an MRTD from the allowlist
    /// @param mrtd The MRTD measurement
    function removeMRTD(bytes calldata mrtd) external onlyOwner {
        bytes32 key = keccak256(mrtd);
        allowedMRTD[key] = false;
        emit MRTDRemoved(mrtd);
    }

    /// @notice Batch add MRTDs to the allowlist
    /// @param mrtds Array of MRTD measurements (48 bytes each)
    function batchAddMRTD(bytes[] calldata mrtds) external onlyOwner {
        for (uint256 i = 0; i < mrtds.length; i++) {
            bytes32 key = keccak256(mrtds[i]);
            allowedMRTD[key] = true;
            emit MRTDAdded(mrtds[i]);
        }
    }

    /// @notice Batch remove MRTDs from the allowlist
    /// @param mrtds Array of MRTD measurements
    function batchRemoveMRTD(bytes[] calldata mrtds) external onlyOwner {
        for (uint256 i = 0; i < mrtds.length; i++) {
            bytes32 key = keccak256(mrtds[i]);
            allowedMRTD[key] = false;
            emit MRTDRemoved(mrtds[i]);
        }
    }

    /// @notice Check if an MRTD is allowed
    /// @param mrtd The MRTD measurement
    /// @return True if the MRTD is in the allowlist
    function isMRTDAllowed(bytes calldata mrtd) external view returns (bool) {
        bytes32 key = keccak256(mrtd);
        return allowedMRTD[key];
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

    // ============ Combined Check ============

    /// @notice Check if all measurements are valid (MRTD allowed + RTMR1 support level met)
    /// @param mrtd The MRTD measurement
    /// @param rtmr1 RTMR[1] - custom image measurement
    /// @return True if both MRTD is allowed and RTMR1 meets support level
    function isAllowed(bytes calldata mrtd, bytes calldata rtmr1) external view returns (bool) {
        // Check MRTD
        bytes32 mrtdKey = keccak256(mrtd);
        if (!allowedMRTD[mrtdKey]) {
            return false;
        }

        // Check RTMR1 support level
        bytes32 rtmr1Key = keccak256(rtmr1);
        return checkSupport(imageSupport[rtmr1Key], minimumSupportLevel);
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
