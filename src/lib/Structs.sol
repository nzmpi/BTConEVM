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
