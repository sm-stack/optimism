// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IProxyAdminOwnedBase } from "interfaces/universal/IProxyAdminOwnedBase.sol";

/// @title IProofClaimRegistry
/// @notice Interface for the ProofClaimRegistry contract.
interface IProofClaimRegistry is IProxyAdminOwnedBase {
    /// @notice Lifecycle of a claim.
    enum ClaimStatus {
        None,
        Pending,
        Verified
    }

    error ProofClaimRegistry_ClaimExists();
    error ProofClaimRegistry_InsufficientFee();
    error ProofClaimRegistry_TransferFailed();
    error ProofClaimRegistry_OnlySystem();
    error ProofClaimRegistry_WrongAggregationProgram();
    error ProofClaimRegistry_ClaimNotPending();

    event ClaimSubmitted(
        bytes32 indexed claimId,
        bytes32 indexed vkeyHash,
        bytes32 publicValuesDigest,
        address indexed submitter,
        uint256 fee
    );
    event ClaimVerified(bytes32 indexed claimId);
    event AggregationVkeyHashSet(bytes32 aggregationVkeyHash);
    event BlobGasPerClaimSet(uint256 blobGasPerClaim);

    function version() external view returns (string memory);
    function aggregationVkeyHash() external view returns (bytes32);
    function blobGasPerClaim() external view returns (uint256);
    function submitClaim(bytes32 _vkeyHash, bytes memory _publicValues) external payable returns (bytes32 claimId_);
    function finalizeClaims(bytes32 _aggregationVkeyHash, bytes32[] memory _claimIds) external returns (bytes4);
    function setAggregationVkeyHash(bytes32 _aggregationVkeyHash) external;
    function setBlobGasPerClaim(uint256 _blobGasPerClaim) external;
    function claimFee() external view returns (uint256 fee_);
    function claimId(bytes32 _vkeyHash, bytes32 _publicValuesDigest) external pure returns (bytes32);
    function claimStatus(bytes32 _claimId) external view returns (ClaimStatus);
    function isVerified(bytes32 _vkeyHash, bytes32 _publicValuesDigest) external view returns (bool);

    function __constructor__() external;
}
