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
import { IProofRegistry } from "interfaces/L2/IProofRegistry.sol";
import { IProxyAdmin } from "interfaces/universal/IProxyAdmin.sol";
import { IProxyAdminOwnedBase } from "interfaces/universal/IProxyAdminOwnedBase.sol";

/// @title ProofRegistry_TestInit
/// @notice Reusable test initialization for `ProofRegistry` tests. Genesis installs the
///         registry because the PROOF_AGGREGATION dev feature is enabled.
abstract contract ProofRegistry_TestInit is CommonTest {
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

    address internal constant SYSTEM_ADDRESS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    bytes32 internal constant AGGREGATION_VKEY = bytes32(uint256(0xa99));
    bytes32 internal constant VKEY = bytes32(uint256(0x5e1));
    uint256 internal constant BLOB_BASE_FEE = 7 gwei;
    uint256 internal constant BLOB_GAS_PER_STATEMENT = 131_072;

    IProofRegistry internal registry = IProofRegistry(Predeploys.PROOF_REGISTRY);
    address internal owner;

    function setUp() public virtual override {
        setDevFeatureEnabled(DevFeatures.PROOF_AGGREGATION);
        super.setUp();
        owner = IProxyAdmin(Predeploys.PROXY_ADMIN).owner();
        vm.mockCall(Predeploys.L1_BLOCK_ATTRIBUTES, abi.encodeCall(IL1Block.blobBaseFee, ()), abi.encode(BLOB_BASE_FEE));
    }

    /// @notice Configures the registry the way an operator would.
    function _configure() internal {
        vm.startPrank(owner);
        registry.setAggregationVkeyHash(AGGREGATION_VKEY);
        registry.setBlobGasPerStatement(BLOB_GAS_PER_STATEMENT);
        vm.stopPrank();
    }

    /// @notice Submits a statement from `alice`, paying exactly the fee.
    function _submit(bytes memory _publicValues) internal returns (bytes32 statementId_) {
        uint256 fee = registry.statementFee();
        vm.prank(alice);
        statementId_ = registry.submitStatement{ value: fee }(VKEY, _publicValues);
    }

    function _ids(bytes32 _a) internal pure returns (bytes32[] memory ids_) {
        ids_ = new bytes32[](1);
        ids_[0] = _a;
    }
}

/// @title ProofRegistry_Uncategorized_Test
/// @notice Tests that genesis installs the registry behind its predeploy proxy.
contract ProofRegistry_Uncategorized_Test is ProofRegistry_TestInit {
    /// @notice The registry is live at its predeploy address with the expected implementation.
    function test_genesis_installsRegistry_succeeds() external view {
        assertEq(
            EIP1967Helper.getImplementation(Predeploys.PROOF_REGISTRY),
            Predeploys.predeployToCodeNamespace(Predeploys.PROOF_REGISTRY)
        );
        assertEq(registry.version(), "1.0.0");
        assertEq(registry.aggregationVkeyHash(), bytes32(0));
        assertEq(registry.blobGasPerStatement(), 0);
        assertEq(IProxyAdminOwnedBase(address(registry)).proxyAdminOwner(), owner);
    }
}

/// @title ProofRegistry_StatementId_Test
/// @notice Tests the statement id encoding shared with the execution client.
contract ProofRegistry_StatementId_Test is ProofRegistry_TestInit {
    /// @notice Same vector as op-alloy's `statement_id_matches_registry_encoding`.
    function test_statementId_matchesExecutionClient_succeeds() external view {
        assertEq(
            registry.statementId(
                0x2222222222222222222222222222222222222222222222222222222222222222,
                0x3333333333333333333333333333333333333333333333333333333333333333
            ),
            0xf3357627f4934d47fe409005b05c900777a6d97ec3788304e2d9c7b4d322cd4d
        );
    }
}

/// @title ProofRegistry_SubmitStatement_Test
/// @notice Tests the `submitStatement` function.
contract ProofRegistry_SubmitStatement_Test is ProofRegistry_TestInit {
    /// @notice A statement becomes pending, pays its fee to the SequencerFeeVault and refunds the rest.
    function test_submitStatement_paysFeeAndRefundsExcess_succeeds() external {
        _configure();
        bytes memory publicValues = hex"c0ffee";
        uint256 fee = BLOB_BASE_FEE * BLOB_GAS_PER_STATEMENT;
        assertEq(registry.statementFee(), fee);

        bytes32 expectedId = registry.statementId(VKEY, sha256(publicValues));
        uint256 aliceBefore = alice.balance;
        uint256 vaultBefore = Predeploys.SEQUENCER_FEE_WALLET.balance;

        vm.expectEmit(address(registry));
        emit StatementSubmitted(expectedId, VKEY, sha256(publicValues), alice, fee);
        vm.prank(alice);
        bytes32 id = registry.submitStatement{ value: fee + 1 ether }(VKEY, publicValues);

        assertEq(id, expectedId);
        assertEq(uint8(registry.statementStatus(id)), uint8(IProofRegistry.StatementStatus.Pending));
        assertFalse(registry.isVerified(VKEY, sha256(publicValues)));
        assertEq(Predeploys.SEQUENCER_FEE_WALLET.balance, vaultBefore + fee);
        assertEq(alice.balance, aliceBefore - fee);
        assertEq(address(registry).balance, 0);
    }

    /// @notice With no blob gas configured, statements are free.
    function test_submitStatement_zeroFee_succeeds() external {
        vm.prank(alice);
        bytes32 id = registry.submitStatement(VKEY, hex"01");
        assertEq(uint8(registry.statementStatus(id)), uint8(IProofRegistry.StatementStatus.Pending));
    }

    /// @notice Paying less than the fee reverts.
    function test_submitStatement_insufficientFee_reverts() external {
        _configure();
        uint256 fee = registry.statementFee();
        vm.prank(alice);
        vm.expectRevert(IProofRegistry.ProofRegistry_InsufficientFee.selector);
        registry.submitStatement{ value: fee - 1 }(VKEY, hex"01");
    }

    /// @notice The same statement cannot be submitted twice.
    function test_submitStatement_duplicate_reverts() external {
        _submit(hex"01");
        vm.prank(alice);
        vm.expectRevert(IProofRegistry.ProofRegistry_StatementExists.selector);
        registry.submitStatement(VKEY, hex"01");
    }
}

/// @title ProofRegistry_VerifyStatements_Test
/// @notice Tests the `verifyStatements` function.
contract ProofRegistry_VerifyStatements_Test is ProofRegistry_TestInit {
    /// @notice The system address verifies pending statements and gets the selector back.
    function test_verifyStatements_pendingStatements_succeeds() external {
        _configure();
        bytes32 a = _submit(hex"0a");
        bytes32 b = _submit(hex"0b");
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = a;
        ids[1] = b;

        vm.expectEmit(address(registry));
        emit StatementVerified(a);
        vm.expectEmit(address(registry));
        emit StatementVerified(b);
        vm.prank(SYSTEM_ADDRESS);
        bytes4 ack = registry.verifyStatements(AGGREGATION_VKEY, ids);

        assertEq(ack, IProofRegistry.verifyStatements.selector);
        assertTrue(registry.isVerified(VKEY, sha256(hex"0a")));
        assertTrue(registry.isVerified(VKEY, sha256(hex"0b")));
    }

    /// @notice Only the system address can verify statements.
    function testFuzz_verifyStatements_notSystem_reverts(address _caller) external {
        vm.assume(_caller != SYSTEM_ADDRESS);
        _configure();
        bytes32 id = _submit(hex"01");
        vm.prank(_caller);
        vm.expectRevert(IProofRegistry.ProofRegistry_OnlySystem.selector);
        registry.verifyStatements(AGGREGATION_VKEY, _ids(id));
    }

    /// @notice An aggregate from another aggregation program cannot verify statements.
    function test_verifyStatements_wrongAggregationProgram_reverts() external {
        _configure();
        bytes32 id = _submit(hex"01");
        vm.prank(SYSTEM_ADDRESS);
        vm.expectRevert(IProofRegistry.ProofRegistry_WrongAggregationProgram.selector);
        registry.verifyStatements(bytes32(uint256(1)), _ids(id));
    }

    /// @notice Nothing can be verified before an aggregation program is configured.
    function test_verifyStatements_unconfigured_reverts() external {
        bytes32 id = _submit(hex"01");
        vm.prank(SYSTEM_ADDRESS);
        vm.expectRevert(IProofRegistry.ProofRegistry_WrongAggregationProgram.selector);
        registry.verifyStatements(bytes32(0), _ids(id));
    }

    /// @notice A statement nobody submitted cannot be verified.
    function test_verifyStatements_unsubmittedStatement_reverts() external {
        _configure();
        vm.prank(SYSTEM_ADDRESS);
        vm.expectRevert(IProofRegistry.ProofRegistry_StatementNotPending.selector);
        registry.verifyStatements(AGGREGATION_VKEY, _ids(bytes32(uint256(42))));
    }

    /// @notice A statement cannot be verified twice.
    function test_verifyStatements_alreadyVerified_reverts() external {
        _configure();
        bytes32 id = _submit(hex"01");
        vm.startPrank(SYSTEM_ADDRESS);
        registry.verifyStatements(AGGREGATION_VKEY, _ids(id));
        vm.expectRevert(IProofRegistry.ProofRegistry_StatementNotPending.selector);
        registry.verifyStatements(AGGREGATION_VKEY, _ids(id));
        vm.stopPrank();
    }
}

/// @title ProofRegistry_SetAggregationVkeyHash_Test
/// @notice Tests the `setAggregationVkeyHash` function.
contract ProofRegistry_SetAggregationVkeyHash_Test is ProofRegistry_TestInit {
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

/// @title ProofRegistry_SetBlobGasPerStatement_Test
/// @notice Tests the `setBlobGasPerStatement` function.
contract ProofRegistry_SetBlobGasPerStatement_Test is ProofRegistry_TestInit {
    /// @notice The proxy admin owner sets the blob gas per statement.
    function test_setBlobGasPerStatement_owner_succeeds() external {
        vm.expectEmit(address(registry));
        emit BlobGasPerStatementSet(BLOB_GAS_PER_STATEMENT);
        vm.prank(owner);
        registry.setBlobGasPerStatement(BLOB_GAS_PER_STATEMENT);
        assertEq(registry.blobGasPerStatement(), BLOB_GAS_PER_STATEMENT);
    }

    /// @notice Anyone else cannot set the blob gas per statement.
    function testFuzz_setBlobGasPerStatement_notOwner_reverts(address _caller) external {
        vm.assume(_caller != owner);
        vm.prank(_caller);
        vm.expectRevert(IProxyAdminOwnedBase.ProxyAdminOwnedBase_NotProxyAdminOwner.selector);
        registry.setBlobGasPerStatement(BLOB_GAS_PER_STATEMENT);
    }
}
