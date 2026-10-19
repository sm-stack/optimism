// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Testing
import { CommonTest } from "test/setup/CommonTest.sol";
import { EIP1967Helper } from "test/mocks/EIP1967Helper.sol";

// Libraries
import { DevFeatures } from "src/libraries/DevFeatures.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";

// Interfaces
import { IL1Block } from "interfaces/L2/IL1Block.sol";
import { IProofClaimRegistry } from "interfaces/L2/IProofClaimRegistry.sol";
import { IProxyAdmin } from "interfaces/universal/IProxyAdmin.sol";
import { IProxyAdminOwnedBase } from "interfaces/universal/IProxyAdminOwnedBase.sol";

/// @title ProofClaimRegistry_TestInit
/// @notice Reusable test initialization for `ProofClaimRegistry` tests. Genesis installs the
///         registry because the PROOF_CLAIMS dev feature is enabled.
abstract contract ProofClaimRegistry_TestInit is CommonTest {
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

    address internal constant SYSTEM_ADDRESS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    bytes32 internal constant AGGREGATION_VKEY = bytes32(uint256(0xa99));
    bytes32 internal constant VKEY = bytes32(uint256(0x5e1));
    uint256 internal constant BLOB_BASE_FEE = 7 gwei;
    uint256 internal constant BLOB_GAS_PER_CLAIM = 131_072;

    IProofClaimRegistry internal registry = IProofClaimRegistry(Predeploys.PROOF_CLAIM_REGISTRY);
    address internal owner;

    function setUp() public virtual override {
        setDevFeatureEnabled(DevFeatures.PROOF_CLAIMS);
        super.setUp();
        owner = IProxyAdmin(Predeploys.PROXY_ADMIN).owner();
        vm.mockCall(Predeploys.L1_BLOCK_ATTRIBUTES, abi.encodeCall(IL1Block.blobBaseFee, ()), abi.encode(BLOB_BASE_FEE));
    }

    /// @notice Configures the registry the way an operator would.
    function _configure() internal {
        vm.startPrank(owner);
        registry.setAggregationVkeyHash(AGGREGATION_VKEY);
        registry.setBlobGasPerClaim(BLOB_GAS_PER_CLAIM);
        vm.stopPrank();
    }

    /// @notice Submits a claim from `alice`, paying exactly the fee.
    function _submit(bytes memory _publicValues) internal returns (bytes32 claimId_) {
        uint256 fee = registry.claimFee();
        vm.prank(alice);
        claimId_ = registry.submitClaim{ value: fee }(VKEY, _publicValues);
    }

    function _ids(bytes32 _a) internal pure returns (bytes32[] memory ids_) {
        ids_ = new bytes32[](1);
        ids_[0] = _a;
    }
}

/// @title ProofClaimRegistry_Uncategorized_Test
/// @notice Tests that genesis installs the registry behind its predeploy proxy.
contract ProofClaimRegistry_Uncategorized_Test is ProofClaimRegistry_TestInit {
    /// @notice The registry is live at its predeploy address with the expected implementation.
    function test_genesis_installsRegistry_succeeds() external view {
        assertEq(
            EIP1967Helper.getImplementation(Predeploys.PROOF_CLAIM_REGISTRY),
            Predeploys.predeployToCodeNamespace(Predeploys.PROOF_CLAIM_REGISTRY)
        );
        assertEq(registry.version(), "1.0.0");
        assertEq(registry.aggregationVkeyHash(), bytes32(0));
        assertEq(registry.blobGasPerClaim(), 0);
        assertEq(IProxyAdminOwnedBase(address(registry)).proxyAdminOwner(), owner);
    }
}

/// @title ProofClaimRegistry_ClaimId_Test
/// @notice Tests the claim id encoding shared with the execution client.
contract ProofClaimRegistry_ClaimId_Test is ProofClaimRegistry_TestInit {
    /// @notice Same vector as op-alloy's `claim_id_matches_registry_encoding`.
    function test_claimId_matchesExecutionClient_succeeds() external view {
        assertEq(
            registry.claimId(
                0x2222222222222222222222222222222222222222222222222222222222222222,
                0x3333333333333333333333333333333333333333333333333333333333333333
            ),
            0xf3357627f4934d47fe409005b05c900777a6d97ec3788304e2d9c7b4d322cd4d
        );
    }
}

/// @title ProofClaimRegistry_SubmitClaim_Test
/// @notice Tests the `submitClaim` function.
contract ProofClaimRegistry_SubmitClaim_Test is ProofClaimRegistry_TestInit {
    /// @notice A claim becomes pending, pays its fee to the SequencerFeeVault and refunds the rest.
    function test_submitClaim_paysFeeAndRefundsExcess_succeeds() external {
        _configure();
        bytes memory publicValues = hex"c0ffee";
        uint256 fee = BLOB_BASE_FEE * BLOB_GAS_PER_CLAIM;
        assertEq(registry.claimFee(), fee);

        bytes32 expectedId = registry.claimId(VKEY, sha256(publicValues));
        uint256 aliceBefore = alice.balance;
        uint256 vaultBefore = Predeploys.SEQUENCER_FEE_WALLET.balance;

        vm.expectEmit(address(registry));
        emit ClaimSubmitted(expectedId, VKEY, sha256(publicValues), alice, fee);
        vm.prank(alice);
        bytes32 id = registry.submitClaim{ value: fee + 1 ether }(VKEY, publicValues);

        assertEq(id, expectedId);
        assertEq(uint8(registry.claimStatus(id)), uint8(IProofClaimRegistry.ClaimStatus.Pending));
        assertFalse(registry.isVerified(VKEY, sha256(publicValues)));
        assertEq(Predeploys.SEQUENCER_FEE_WALLET.balance, vaultBefore + fee);
        assertEq(alice.balance, aliceBefore - fee);
        assertEq(address(registry).balance, 0);
    }

    /// @notice With no blob gas configured, claims are free.
    function test_submitClaim_zeroFee_succeeds() external {
        vm.prank(alice);
        bytes32 id = registry.submitClaim(VKEY, hex"01");
        assertEq(uint8(registry.claimStatus(id)), uint8(IProofClaimRegistry.ClaimStatus.Pending));
    }

    /// @notice Paying less than the fee reverts.
    function test_submitClaim_insufficientFee_reverts() external {
        _configure();
        uint256 fee = registry.claimFee();
        vm.prank(alice);
        vm.expectRevert(IProofClaimRegistry.ProofClaimRegistry_InsufficientFee.selector);
        registry.submitClaim{ value: fee - 1 }(VKEY, hex"01");
    }

    /// @notice The same claim cannot be submitted twice.
    function test_submitClaim_duplicate_reverts() external {
        _submit(hex"01");
        vm.prank(alice);
        vm.expectRevert(IProofClaimRegistry.ProofClaimRegistry_ClaimExists.selector);
        registry.submitClaim(VKEY, hex"01");
    }
}

/// @title ProofClaimRegistry_FinalizeClaims_Test
/// @notice Tests the `finalizeClaims` function.
contract ProofClaimRegistry_FinalizeClaims_Test is ProofClaimRegistry_TestInit {
    /// @notice The system address finalizes pending claims and gets the selector back.
    function test_finalizeClaims_pendingClaims_succeeds() external {
        _configure();
        bytes32 a = _submit(hex"0a");
        bytes32 b = _submit(hex"0b");
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = a;
        ids[1] = b;

        vm.expectEmit(address(registry));
        emit ClaimVerified(a);
        vm.expectEmit(address(registry));
        emit ClaimVerified(b);
        vm.prank(SYSTEM_ADDRESS);
        bytes4 ack = registry.finalizeClaims(AGGREGATION_VKEY, ids);

        assertEq(ack, IProofClaimRegistry.finalizeClaims.selector);
        assertTrue(registry.isVerified(VKEY, sha256(hex"0a")));
        assertTrue(registry.isVerified(VKEY, sha256(hex"0b")));
    }

    /// @notice Only the system address can finalize claims.
    function testFuzz_finalizeClaims_notSystem_reverts(address _caller) external {
        vm.assume(_caller != SYSTEM_ADDRESS);
        _configure();
        bytes32 id = _submit(hex"01");
        vm.prank(_caller);
        vm.expectRevert(IProofClaimRegistry.ProofClaimRegistry_OnlySystem.selector);
        registry.finalizeClaims(AGGREGATION_VKEY, _ids(id));
    }

    /// @notice An aggregate from another aggregation program cannot finalize claims.
    function test_finalizeClaims_wrongAggregationProgram_reverts() external {
        _configure();
        bytes32 id = _submit(hex"01");
        vm.prank(SYSTEM_ADDRESS);
        vm.expectRevert(IProofClaimRegistry.ProofClaimRegistry_WrongAggregationProgram.selector);
        registry.finalizeClaims(bytes32(uint256(1)), _ids(id));
    }

    /// @notice Nothing can be finalized before an aggregation program is configured.
    function test_finalizeClaims_unconfigured_reverts() external {
        bytes32 id = _submit(hex"01");
        vm.prank(SYSTEM_ADDRESS);
        vm.expectRevert(IProofClaimRegistry.ProofClaimRegistry_WrongAggregationProgram.selector);
        registry.finalizeClaims(bytes32(0), _ids(id));
    }

    /// @notice A claim nobody submitted cannot be finalized.
    function test_finalizeClaims_unsubmittedClaim_reverts() external {
        _configure();
        vm.prank(SYSTEM_ADDRESS);
        vm.expectRevert(IProofClaimRegistry.ProofClaimRegistry_ClaimNotPending.selector);
        registry.finalizeClaims(AGGREGATION_VKEY, _ids(bytes32(uint256(42))));
    }

    /// @notice A claim cannot be finalized twice.
    function test_finalizeClaims_alreadyVerified_reverts() external {
        _configure();
        bytes32 id = _submit(hex"01");
        vm.startPrank(SYSTEM_ADDRESS);
        registry.finalizeClaims(AGGREGATION_VKEY, _ids(id));
        vm.expectRevert(IProofClaimRegistry.ProofClaimRegistry_ClaimNotPending.selector);
        registry.finalizeClaims(AGGREGATION_VKEY, _ids(id));
        vm.stopPrank();
    }
}

/// @title ProofClaimRegistry_SetAggregationVkeyHash_Test
/// @notice Tests the `setAggregationVkeyHash` function.
contract ProofClaimRegistry_SetAggregationVkeyHash_Test is ProofClaimRegistry_TestInit {
    /// @notice The proxy admin owner sets the aggregation program.
    function test_setAggregationVkeyHash_owner_succeeds() external {
        vm.expectEmit(address(registry));
        emit AggregationVkeyHashSet(AGGREGATION_VKEY);
        vm.prank(owner);
        registry.setAggregationVkeyHash(AGGREGATION_VKEY);
        assertEq(registry.aggregationVkeyHash(), AGGREGATION_VKEY);
    }

    /// @notice Anyone else cannot set the aggregation program.
    function testFuzz_setAggregationVkeyHash_notOwner_reverts(address _caller) external {
        vm.assume(_caller != owner);
        vm.prank(_caller);
        vm.expectRevert(IProxyAdminOwnedBase.ProxyAdminOwnedBase_NotProxyAdminOwner.selector);
        registry.setAggregationVkeyHash(AGGREGATION_VKEY);
    }
}

/// @title ProofClaimRegistry_SetBlobGasPerClaim_Test
/// @notice Tests the `setBlobGasPerClaim` function.
contract ProofClaimRegistry_SetBlobGasPerClaim_Test is ProofClaimRegistry_TestInit {
    /// @notice The proxy admin owner sets the blob gas per claim.
    function test_setBlobGasPerClaim_owner_succeeds() external {
        vm.expectEmit(address(registry));
        emit BlobGasPerClaimSet(BLOB_GAS_PER_CLAIM);
        vm.prank(owner);
        registry.setBlobGasPerClaim(BLOB_GAS_PER_CLAIM);
        assertEq(registry.blobGasPerClaim(), BLOB_GAS_PER_CLAIM);
    }

    /// @notice Anyone else cannot set the blob gas per claim.
    function testFuzz_setBlobGasPerClaim_notOwner_reverts(address _caller) external {
        vm.assume(_caller != owner);
        vm.prank(_caller);
        vm.expectRevert(IProxyAdminOwnedBase.ProxyAdminOwnedBase_NotProxyAdminOwner.selector);
        registry.setBlobGasPerClaim(BLOB_GAS_PER_CLAIM);
    }
}
