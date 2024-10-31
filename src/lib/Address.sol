// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Base58.sol";
import "./Bech32.sol";
import {SerialLib} from "./SerialLib.sol";
import {Point} from "./Structs.sol";
import {ScriptType} from "./Types.sol";
import "./Utils.sol";

/**
 * @title Address library
 * @notice Some helper functions for Bitcoin addresses
 * @author https://github.com/nzmpi
 */
library Address {
    using Base58 for bytes;
    using Bech32 for *;
    using SerialLib for Point;
    using Utils for bytes;

    error ChecksumFailed();
    error NotSupported(ScriptType _type);
    error WrongHashLength();

    /**
     * Calculates the Bitcoin address from a hash
     * @param _hash - The hash to calculate the address from
     * @param _isMainnet - Whether the address is mainnet or not
     * @param _type - The type of the Script
     * @return res - The calculated address
     */
    function getAddress(bytes memory _hash, bool _isMainnet, ScriptType _type)
        internal
        pure
        returns (bytes memory res)
    {
        uint8 prefix;
        if (_type == ScriptType.P2PKH) {
            prefix = _isMainnet ? 0x00 : 0x6f;
        } else if (_type == ScriptType.P2SH) {
            prefix = _isMainnet ? 0x05 : 0xc4;
        } else if (_type == ScriptType.P2WPKH) {
            return _hash.encode(_isMainnet);
        } else if (_type == ScriptType.P2WSH) {
            return _hash.encode(_isMainnet);
        } else {
            revert NotSupported(_type);
        }

        if (_hash.length != 20) revert WrongHashLength();
        res = bytes.concat(bytes1(prefix), _hash);
        res = bytes.concat(res, bytes4(res.hash256())).encode();
    }

    /**
     * Checks if the address has a valid checksum
     * @dev Fails if the address has an invalid checksum, otherwise does nothing
     * @param _address - The address to check
     */
    function checksum(bytes memory _address) internal pure {
        bytes3 prefix = bytes3(_address);
        if (prefix == Bech32.BC1 || prefix == Bech32.TB1) {
            if (!_address.verifyChecksum()) revert ChecksumFailed();
        } else {
            bytes memory decoded = _address.decode();
            // 21 = 20 bytes of hash + 1 byte of prefix
            bytes memory hash = decoded.readFromMemory(0, 21);
            if (bytes4(hash.hash256()) != bytes4(decoded.readFromMemory(21, 4))) revert ChecksumFailed();
        }
    }

    /**
     * Gets the hash from an address
     * @param _address - The address to get the hash from
     * @return res - The hash
     */
    function getHashFromAddress(bytes memory _address) internal pure returns (bytes memory) {
        checksum(_address);
        bytes3 prefix = bytes3(_address);
        if (prefix == Bech32.BC1 || prefix == Bech32.TB1) {
            return _address.getHash();
        } else {
            return _address.decode().readFromMemory(1, 20);
        }
    }
}
