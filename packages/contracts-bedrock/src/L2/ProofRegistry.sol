// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Contracts
import { ProxyAdminOwnedBase } from "src/universal/ProxyAdminOwnedBase.sol";

// Libraries
import { Predeploys } from "src/libraries/Predeploys.sol";
import { SafeCall } from "src/libraries/SafeCall.sol";

// Interfaces
import { ISemver } from "interfaces/universal/ISemver.sol";
import { IL1Block } from "interfaces/L2/IL1Block.sol";

/// @custom:proxied true
/// @custom:predeploy 0x4200000000000000000000000000000000000031
/// @title ProofRegistry
/// @notice Records statements of the form "the SP1 program with verifying key digest V produced a
///         valid proof of public values P", without the proof going on chain. A user submits a
///         statement, V and P, and pays its share of the data availability cost of the aggregate proof that
///         will cover it. The statement stays pending until the sequencer includes a proof aggregate
///         transaction whose SP1 proof recursively verified the proof behind it. The execution
///         client verifies that aggregate proof and then calls `verifyStatements` from the system
///         address, which marks the statements verified.
contract ProofRegistry is ProxyAdminOwnedBase, ISemver {
    /// @notice Lifecycle of a statement.
    enum StatementStatus {
        None,
        Pending,
        Verified
    }

    /// @notice Address the execution client calls `verifyStatements` from.
    address internal constant SYSTEM_ADDRESS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;

    /// @notice Semantic version.
    /// @custom:semver 1.0.0
    string public constant version = "1.0.0";

    /// @notice Status of each statement, keyed by statement id.
    mapping(bytes32 => StatementStatus) internal _statementStatus;

    /// @notice Verifying key digest of the aggregation program whose proofs verify statements.
    bytes32 public aggregationVkeyHash;

    /// @notice L1 blob gas each statement pays for at the current L1 blob base fee: its share of the
    ///         blobs that carry the aggregate proof.
    uint256 public blobGasPerStatement;

    /// @notice Thrown when a statement that was already submitted is submitted again.
    error ProofRegistry_StatementExists();

    /// @notice Thrown when the value sent does not cover the statement fee.
    error ProofRegistry_InsufficientFee();

    /// @notice Thrown when the fee cannot be forwarded or the excess cannot be refunded.
    error ProofRegistry_TransferFailed();

    /// @notice Thrown when `verifyStatements` is not called from the system address.
    error ProofRegistry_OnlySystem();

    /// @notice Thrown when an aggregate comes from an aggregation program other than the
    ///         configured one, or none is configured.
    error ProofRegistry_WrongAggregationProgram();

    /// @notice Thrown when verifying a statement that is not pending.
    error ProofRegistry_StatementNotPending();

    /// @notice Emitted when a statement is submitted.
    /// @param statementId            Id of the statement.
    /// @param vkeyHash           Verifying key digest of the program.
    /// @param publicValuesDigest SHA-256 of the public values.
    /// @param submitter          Account that submitted the statement.
    /// @param fee                Fee paid for the statement.
    event StatementSubmitted(
        bytes32 indexed statementId,
        bytes32 indexed vkeyHash,
        bytes32 publicValuesDigest,
        address indexed submitter,
        uint256 fee
    );

    /// @notice Emitted when a statement is verified by an aggregate proof.
    /// @param statementId Id of the statement.
    event StatementVerified(bytes32 indexed statementId);

    /// @notice Emitted when the aggregation program is changed.
    /// @param aggregationVkeyHash New aggregation program verifying key digest.
    event AggregationVkeyHashSet(bytes32 aggregationVkeyHash);

    /// @notice Emitted when the blob gas charged per statement is changed.
    /// @param blobGasPerStatement New blob gas per statement.
    event BlobGasPerStatementSet(uint256 blobGasPerStatement);

    /// @notice Submits a statement and pays its data availability fee. The fee goes to the
    ///         SequencerFeeVault, which pays for the blobs carrying the aggregate proof; any excess
    ///         is refunded.
    /// @param _vkeyHash     Verifying key digest of the SP1 program, as eight big-endian words.
    /// @param _publicValues Public values the program committed.
    /// @return statementId_ Id of the statement.
    function submitStatement(
        bytes32 _vkeyHash,
        bytes calldata _publicValues
    )
        external
        payable
        returns (bytes32 statementId_)
    {
        bytes32 publicValuesDigest = sha256(_publicValues);
        statementId_ = statementId(_vkeyHash, publicValuesDigest);
        if (_statementStatus[statementId_] != StatementStatus.None) revert ProofRegistry_StatementExists();

        uint256 fee = statementFee();
        if (msg.value < fee) revert ProofRegistry_InsufficientFee();

        _statementStatus[statementId_] = StatementStatus.Pending;
        emit StatementSubmitted(statementId_, _vkeyHash, publicValuesDigest, msg.sender, fee);

        if (fee > 0 && !SafeCall.send(Predeploys.SEQUENCER_FEE_WALLET, fee)) {
            revert ProofRegistry_TransferFailed();
        }
        uint256 excess = msg.value - fee;
        if (excess > 0 && !SafeCall.send(msg.sender, excess)) revert ProofRegistry_TransferFailed();
    }

    /// @notice Marks the statements covered by a verified aggregate proof as verified. Called by the
    ///         execution client from the system address after it verified the aggregate proof of
    ///         the program `_aggregationVkeyHash` over exactly these statements. A revert invalidates the
    ///         block that carries the aggregate, so every statement must be pending: an aggregate cannot
    ///         verify a statement nobody paid for, or verify one twice.
    /// @param _aggregationVkeyHash Verifying key digest of the program that produced the aggregate.
    /// @param _statementIds            Ids of the statements the aggregate covers.
    /// @return This function's selector, which the execution client requires as acknowledgement
    ///         because a call to an address without code also succeeds.
    function verifyStatements(bytes32 _aggregationVkeyHash, bytes32[] calldata _statementIds)
        external
        returns (bytes4)
    {
        if (msg.sender != SYSTEM_ADDRESS) revert ProofRegistry_OnlySystem();
        if (_aggregationVkeyHash == bytes32(0) || _aggregationVkeyHash != aggregationVkeyHash) {
            revert ProofRegistry_WrongAggregationProgram();
        }

        for (uint256 i = 0; i < _statementIds.length; i++) {
            bytes32 id = _statementIds[i];
            if (_statementStatus[id] != StatementStatus.Pending) revert ProofRegistry_StatementNotPending();
            _statementStatus[id] = StatementStatus.Verified;
            emit StatementVerified(id);
        }

        return this.verifyStatements.selector;
    }

    /// @notice Sets the aggregation program whose proofs verify statements.
    /// @param _aggregationVkeyHash Verifying key digest of the aggregation program.
    function setAggregationVkeyHash(bytes32 _aggregationVkeyHash) external {
        _assertOnlyProxyAdminOwner();
        aggregationVkeyHash = _aggregationVkeyHash;
        emit AggregationVkeyHashSet(_aggregationVkeyHash);
    }

    /// @notice Sets the L1 blob gas each statement pays for.
    /// @param _blobGasPerStatement Blob gas per statement.
    function setBlobGasPerStatement(uint256 _blobGasPerStatement) external {
        _assertOnlyProxyAdminOwner();
        blobGasPerStatement = _blobGasPerStatement;
        emit BlobGasPerStatementSet(_blobGasPerStatement);
    }

    /// @notice Returns the fee to submit a statement now: `blobGasPerStatement` at the L1 blob base fee.
    /// @return fee_ Fee in wei.
    function statementFee() public view returns (uint256 fee_) {
        fee_ = IL1Block(Predeploys.L1_BLOCK_ATTRIBUTES).blobBaseFee() * blobGasPerStatement;
    }

    /// @notice Returns the id of a statement: `keccak256(vkeyHash || publicValuesDigest)`.
    /// @param _vkeyHash           Verifying key digest of the SP1 program.
    /// @param _publicValuesDigest SHA-256 of the public values.
    /// @return Id of the statement.
    function statementId(bytes32 _vkeyHash, bytes32 _publicValuesDigest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_vkeyHash, _publicValuesDigest));
    }

    /// @notice Returns the status of a statement.
    /// @param _statementId Id of the statement.
    /// @return Status of the statement.
    function statementStatus(bytes32 _statementId) external view returns (StatementStatus) {
        return _statementStatus[_statementId];
    }

    /// @notice Returns whether the SP1 program `_vkeyHash` was shown to produce a valid proof of
    ///         public values with SHA-256 digest `_publicValuesDigest`.
    /// @param _vkeyHash           Verifying key digest of the SP1 program.
    /// @param _publicValuesDigest SHA-256 of the public values.
    /// @return True once an aggregate proof covering the statement was verified.
    function isVerified(bytes32 _vkeyHash, bytes32 _publicValuesDigest) external view returns (bool) {
        return _statementStatus[statementId(_vkeyHash, _publicValuesDigest)] == StatementStatus.Verified;
    }
}
