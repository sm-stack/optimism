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
/// @title ProofClaimRegistry
/// @notice Records claims that an SP1 program produced a valid proof, without the proof going on
///         chain. A user submits a claim, the SP1 program's verifying key digest and its public
///         values, and pays its share of the data availability cost of the aggregate proof that
///         will cover it. The claim stays pending until the sequencer includes a claim aggregate
///         transaction whose SP1 proof recursively verified the proof behind it. The execution
///         client verifies that aggregate proof and then calls `finalizeClaims` from the system
///         address, which marks the claims verified.
contract ProofClaimRegistry is ProxyAdminOwnedBase, ISemver {
    /// @notice Lifecycle of a claim.
    enum ClaimStatus {
        None,
        Pending,
        Verified
    }

    /// @notice Address the execution client calls `finalizeClaims` from.
    address internal constant SYSTEM_ADDRESS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;

    /// @notice Semantic version.
    /// @custom:semver 1.0.0
    string public constant version = "1.0.0";

    /// @notice Status of each claim, keyed by claim id.
    mapping(bytes32 => ClaimStatus) internal _claimStatus;

    /// @notice Verifying key digest of the aggregation program whose proofs finalize claims.
    bytes32 public aggregationVkeyHash;

    /// @notice L1 blob gas each claim pays for at the current L1 blob base fee: its share of the
    ///         blobs that carry the aggregate proof.
    uint256 public blobGasPerClaim;

    /// @notice Thrown when a claim that was already submitted is submitted again.
    error ProofClaimRegistry_ClaimExists();

    /// @notice Thrown when the value sent does not cover the claim fee.
    error ProofClaimRegistry_InsufficientFee();

    /// @notice Thrown when the fee cannot be forwarded or the excess cannot be refunded.
    error ProofClaimRegistry_TransferFailed();

    /// @notice Thrown when `finalizeClaims` is not called from the system address.
    error ProofClaimRegistry_OnlySystem();

    /// @notice Thrown when an aggregate comes from an aggregation program other than the
    ///         configured one, or none is configured.
    error ProofClaimRegistry_WrongAggregationProgram();

    /// @notice Thrown when finalizing a claim that is not pending.
    error ProofClaimRegistry_ClaimNotPending();

    /// @notice Emitted when a claim is submitted.
    /// @param claimId            Id of the claim.
    /// @param vkeyHash           Verifying key digest of the claimed program.
    /// @param publicValuesDigest SHA-256 of the claimed public values.
    /// @param submitter          Account that submitted the claim.
    /// @param fee                Fee paid for the claim.
    event ClaimSubmitted(
        bytes32 indexed claimId,
        bytes32 indexed vkeyHash,
        bytes32 publicValuesDigest,
        address indexed submitter,
        uint256 fee
    );

    /// @notice Emitted when a claim is verified by an aggregate proof.
    /// @param claimId Id of the claim.
    event ClaimVerified(bytes32 indexed claimId);

    /// @notice Emitted when the aggregation program is changed.
    /// @param aggregationVkeyHash New aggregation program verifying key digest.
    event AggregationVkeyHashSet(bytes32 aggregationVkeyHash);

    /// @notice Emitted when the blob gas charged per claim is changed.
    /// @param blobGasPerClaim New blob gas per claim.
    event BlobGasPerClaimSet(uint256 blobGasPerClaim);

    /// @notice Submits a claim and pays its data availability fee. The fee goes to the
    ///         SequencerFeeVault, which pays for the blobs carrying the aggregate proof; any excess
    ///         is refunded.
    /// @param _vkeyHash     Verifying key digest of the SP1 program, as eight big-endian words.
    /// @param _publicValues Public values the program committed.
    /// @return claimId_ Id of the claim.
    function submitClaim(bytes32 _vkeyHash, bytes calldata _publicValues) external payable returns (bytes32 claimId_) {
        bytes32 publicValuesDigest = sha256(_publicValues);
        claimId_ = claimId(_vkeyHash, publicValuesDigest);
        if (_claimStatus[claimId_] != ClaimStatus.None) revert ProofClaimRegistry_ClaimExists();

        uint256 fee = claimFee();
        if (msg.value < fee) revert ProofClaimRegistry_InsufficientFee();

        _claimStatus[claimId_] = ClaimStatus.Pending;
        emit ClaimSubmitted(claimId_, _vkeyHash, publicValuesDigest, msg.sender, fee);

        if (fee > 0 && !SafeCall.send(Predeploys.SEQUENCER_FEE_WALLET, fee)) {
            revert ProofClaimRegistry_TransferFailed();
        }
        uint256 excess = msg.value - fee;
        if (excess > 0 && !SafeCall.send(msg.sender, excess)) revert ProofClaimRegistry_TransferFailed();
    }

    /// @notice Marks the claims covered by a verified aggregate proof as verified. Called by the
    ///         execution client from the system address after it verified the aggregate proof of
    ///         the program `_aggregationVkeyHash` over exactly these claims. A revert invalidates the
    ///         block that carries the aggregate, so every claim must be pending: an aggregate cannot
    ///         finalize a claim nobody paid for, or finalize one twice.
    /// @param _aggregationVkeyHash Verifying key digest of the program that produced the aggregate.
    /// @param _claimIds            Ids of the claims the aggregate covers.
    /// @return This function's selector, which the execution client requires as acknowledgement
    ///         because a call to an address without code also succeeds.
    function finalizeClaims(bytes32 _aggregationVkeyHash, bytes32[] calldata _claimIds) external returns (bytes4) {
        if (msg.sender != SYSTEM_ADDRESS) revert ProofClaimRegistry_OnlySystem();
        if (_aggregationVkeyHash == bytes32(0) || _aggregationVkeyHash != aggregationVkeyHash) {
            revert ProofClaimRegistry_WrongAggregationProgram();
        }

        for (uint256 i = 0; i < _claimIds.length; i++) {
            bytes32 id = _claimIds[i];
            if (_claimStatus[id] != ClaimStatus.Pending) revert ProofClaimRegistry_ClaimNotPending();
            _claimStatus[id] = ClaimStatus.Verified;
            emit ClaimVerified(id);
        }

        return this.finalizeClaims.selector;
    }

    /// @notice Sets the aggregation program whose proofs finalize claims.
    /// @param _aggregationVkeyHash Verifying key digest of the aggregation program.
    function setAggregationVkeyHash(bytes32 _aggregationVkeyHash) external {
        _assertOnlyProxyAdminOwner();
        aggregationVkeyHash = _aggregationVkeyHash;
        emit AggregationVkeyHashSet(_aggregationVkeyHash);
    }

    /// @notice Sets the L1 blob gas each claim pays for.
    /// @param _blobGasPerClaim Blob gas per claim.
    function setBlobGasPerClaim(uint256 _blobGasPerClaim) external {
        _assertOnlyProxyAdminOwner();
        blobGasPerClaim = _blobGasPerClaim;
        emit BlobGasPerClaimSet(_blobGasPerClaim);
    }

    /// @notice Returns the fee to submit a claim now: `blobGasPerClaim` at the L1 blob base fee.
    /// @return fee_ Fee in wei.
    function claimFee() public view returns (uint256 fee_) {
        fee_ = IL1Block(Predeploys.L1_BLOCK_ATTRIBUTES).blobBaseFee() * blobGasPerClaim;
    }

    /// @notice Returns the id of a claim: `keccak256(vkeyHash || publicValuesDigest)`.
    /// @param _vkeyHash           Verifying key digest of the SP1 program.
    /// @param _publicValuesDigest SHA-256 of the public values.
    /// @return Id of the claim.
    function claimId(bytes32 _vkeyHash, bytes32 _publicValuesDigest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_vkeyHash, _publicValuesDigest));
    }

    /// @notice Returns the status of a claim.
    /// @param _claimId Id of the claim.
    /// @return Status of the claim.
    function claimStatus(bytes32 _claimId) external view returns (ClaimStatus) {
        return _claimStatus[_claimId];
    }

    /// @notice Returns whether the SP1 program `_vkeyHash` was shown to produce a valid proof of
    ///         public values with SHA-256 digest `_publicValuesDigest`.
    /// @param _vkeyHash           Verifying key digest of the SP1 program.
    /// @param _publicValuesDigest SHA-256 of the public values.
    /// @return True once an aggregate proof covering the claim was verified.
    function isVerified(bytes32 _vkeyHash, bytes32 _publicValuesDigest) external view returns (bool) {
        return _claimStatus[claimId(_vkeyHash, _publicValuesDigest)] == ClaimStatus.Verified;
    }
}
