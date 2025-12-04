// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title BaseImageAllowlist
/// @notice Allowlist for TDX base image measurements (MRTD, RTMR[0], RTMR[1])
/// @dev These measurements cover firmware/kernel/OS and are stable for a given custom CS image build
contract BaseImageAllowlist {
    address public owner;
    mapping(bytes32 => bool) public allowedBaseImages; // hash of (mrtd, rtmr0, rtmr1)

    event BaseImageAdded(bytes32 indexed key, bytes mrtd, bytes rtmr0, bytes rtmr1);
    event BaseImageRemoved(bytes32 indexed key);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NOT_OWNER();
    error ZERO_ADDRESS();

    modifier onlyOwner() {
        require(msg.sender == owner, NOT_OWNER());
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Add a base image to the allowlist
    /// @param mrtd The MRTD (TD Measurement) - initial TD contents
    /// @param rtmr0 RTMR[0] - Firmware/BIOS measurement
    /// @param rtmr1 RTMR[1] - OS/Kernel measurement
    function addBaseImage(bytes calldata mrtd, bytes calldata rtmr0, bytes calldata rtmr1) external onlyOwner {
        bytes32 key = computeKey(mrtd, rtmr0, rtmr1);
        allowedBaseImages[key] = true;
        emit BaseImageAdded(key, mrtd, rtmr0, rtmr1);
    }

    /// @notice Remove a base image from the allowlist
    /// @param mrtd The MRTD (TD Measurement)
    /// @param rtmr0 RTMR[0] - Firmware/BIOS measurement
    /// @param rtmr1 RTMR[1] - OS/Kernel measurement
    function removeBaseImage(bytes calldata mrtd, bytes calldata rtmr0, bytes calldata rtmr1) external onlyOwner {
        bytes32 key = computeKey(mrtd, rtmr0, rtmr1);
        allowedBaseImages[key] = false;
        emit BaseImageRemoved(key);
    }

    /// @notice Check if a base image is allowed
    /// @param mrtd The MRTD (TD Measurement)
    /// @param rtmr0 RTMR[0] - Firmware/BIOS measurement
    /// @param rtmr1 RTMR[1] - OS/Kernel measurement
    /// @return True if the base image is allowed
    function isAllowed(bytes calldata mrtd, bytes calldata rtmr0, bytes calldata rtmr1) external view returns (bool) {
        bytes32 key = computeKey(mrtd, rtmr0, rtmr1);
        return allowedBaseImages[key];
    }

    /// @notice Compute the key for a base image (useful for debugging)
    /// @param mrtd The MRTD (TD Measurement)
    /// @param rtmr0 RTMR[0] - Firmware/BIOS measurement
    /// @param rtmr1 RTMR[1] - OS/Kernel measurement
    /// @return The keccak256 hash key
    function computeKey(bytes calldata mrtd, bytes calldata rtmr0, bytes calldata rtmr1) public pure returns (bytes32) {
        return keccak256(abi.encode(mrtd, rtmr0, rtmr1));
    }

    /// @notice Transfer ownership to a new address
    /// @param newOwner The new owner address
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), ZERO_ADDRESS());
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
