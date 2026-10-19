// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IProxyAdminOwnedBase } from "interfaces/universal/IProxyAdminOwnedBase.sol";

/// @title IProofRegistry
/// @notice Interface for the ProofRegistry contract.
interface IProofRegistry is IProxyAdminOwnedBase {
    /// @notice Lifecycle of a statement.
    enum StatementStatus {
        None,
        Pending,
        Verified
    }

    error ProofRegistry_StatementExists();
    error ProofRegistry_InsufficientFee();
    error ProofRegistry_TransferFailed();
    error ProofRegistry_OnlySystem();
    error ProofRegistry_WrongAggregationProgram();
    error ProofRegistry_StatementNotPending();

    event StatementSubmitted(
        bytes32 indexed statementId,
        bytes32 indexed vkeyHash,
        bytes32 publicValuesDigest,
        address indexed submitter,
        uint256 fee
    );
    event StatementVerified(bytes32 indexed statementId);
    event AggregationVkeyHashSet(bytes32 aggregationVkeyHash);
    event BlobGasPerStatementSet(uint256 blobGasPerStatement);

    function version() external view returns (string memory);
    function aggregationVkeyHash() external view returns (bytes32);
    function blobGasPerStatement() external view returns (uint256);
    function submitStatement(bytes32 _vkeyHash, bytes memory _publicValues) external payable returns (bytes32 statementId_);
    function verifyStatements(bytes32 _aggregationVkeyHash, bytes32[] memory _statementIds) external returns (bytes4);
    function setAggregationVkeyHash(bytes32 _aggregationVkeyHash) external;
    function setBlobGasPerStatement(uint256 _blobGasPerStatement) external;
    function statementFee() external view returns (uint256 fee_);
    function statementId(bytes32 _vkeyHash, bytes32 _publicValuesDigest) external pure returns (bytes32);
    function statementStatus(bytes32 _statementId) external view returns (StatementStatus);
    function isVerified(bytes32 _vkeyHash, bytes32 _publicValuesDigest) external view returns (bool);

    function __constructor__() external;
}
