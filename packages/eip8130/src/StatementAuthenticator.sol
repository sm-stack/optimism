// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthenticator} from "./interfaces/IAuthenticator.sol";

/// @notice The EIP-8288 statements the executing transaction depends on, from the Transaction Context precompile.
interface ITransactionStatements {
    /// @notice Whether the transaction depends on the statement `(0x20, BLAKE2s(tag || key || hash), vk)`.
    function isTransactionStatement(bytes32 vk, bytes8 tag, bytes32 key, bytes32 hash) external view returns (bool);
}

/// @title StatementAuthenticator
/// @notice The OP Stack STATEMENT authenticator (EIP-8130): an actor is a program and a key, `data = vk || tag || key`,
///         and the actor authenticates `hash` when the program proves it did: the transaction depends on the
///         statement `(0x20, BLAKE2s(tag || key || hash), vk)`, which the block's proof aggregate proves (EIP-8288).
///         A leanSPHINCS key is the case `vk` = the signature program, `tag` = "sphmem01", `key` = the public key.
///         Nodes enshrine this authenticator on the transaction path; this contract gives EVM callers the same answer.
contract StatementAuthenticator is IAuthenticator {
    /// @notice The Transaction Context precompile.
    address public constant TX_CONTEXT = 0x813000000000000000000000000000000000aa02;

    /// @inheritdoc IAuthenticator
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length != 72) return bytes32(0);
        bytes32 vk = bytes32(data[0:32]);
        bytes8 tag = bytes8(data[32:40]);
        bytes32 key = bytes32(data[40:72]);
        if (!ITransactionStatements(TX_CONTEXT).isTransactionStatement(vk, tag, key, hash)) return bytes32(0);
        return keccak256(abi.encodePacked("op-stmt-auth", vk, tag, key));
    }
}
