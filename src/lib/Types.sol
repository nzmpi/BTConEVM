// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @notice Represents the supported type of a script
 */
enum ScriptType {
    P2PK, // Pay-to-public-key
    P2PKH, // Pay-to-public-key-hash
    P2SH, // Pay-to-script-hash
    P2WPKH, // Pay-to-witness-public-key-hash
    P2WSH // Pay-to-witness-script-hash
}
