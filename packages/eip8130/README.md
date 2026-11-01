# EIP-8130 Keystore for the OP Stack

`src/Keystore.sol`, `src/libraries/ActorId.sol` and `src/interfaces/{IAuthenticator,IKeystoreImport}.sol` are copied
unchanged from [base/eip-8130](https://github.com/base/eip-8130) at `812317be00d6829e217e0cc92f75be362fde0711`
(MIT, per-file SPDX headers; Copyright Coinbase). `src/StatementAuthenticator.sol` is the OP Stack STATEMENT
authenticator: an actor whose key is a proven program (EIP-8288), leanSPHINCS included.

Both contracts are deployed at Lagoon through the deterministic deployment proxy (salt 0), by an activation deposit
or, for a chain activating Lagoon at genesis, in the genesis state. The bytecode the clients use is committed under
`op-core/eip8130`; run `./build.sh` (forge, solc 0.8.36) to regenerate it, which must leave it unchanged.
