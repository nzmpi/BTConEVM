// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @notice Represents a block
 */
struct Block {
    bytes4 version;
    bytes4 timestamp;
    bytes4 bits;
    bytes4 nonce;
    bytes32 prevBlock;
    bytes32 merkleRoot;
    bytes32[] transactionHashes;
}

/**
 * @notice Represents a point P(x, y) on the elliptic curve secp256k1
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
    bytes32 txId; // hash of the referenced transaction
    bytes4 vout; // index of the referenced output
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
    bool isSegwit;
    bytes4 version;
    bytes4 locktime;
    TxInput[] inputs;
    TxOutput[] outputs;
    // witness is here, because using it in TxInput returns the unsolvable `stack too deep` error
    bytes[][] witness;
}
