// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @notice Represents a point on the elliptic curve secp256k1
 */
struct Point {
    uint256 x;
    uint256 y;
}

/**
 * @notice Represents a signature
 */
struct Signature {
    uint256 r;
    uint256 s;
}

/**
 * @notice Represents a transaction input
 */
struct TxInput {
    bytes32 txId;
    bytes4 vout;
    bytes4 sequence;
    bytes scriptSig;
}

/**
 * @notice Represents a transaction output
 */
struct TxOutput {
    bytes8 amount;
    bytes scriptPubKey;
}

/**
 * @notice Represents a transaction
 */
struct Transaction {
    bytes4 version;
    bytes4 locktime;
    TxInput[] inputs;
    TxOutput[] outputs;
}
