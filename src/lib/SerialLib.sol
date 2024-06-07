// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Point, Signature} from "./Structs.sol";
import {ECBTC} from "./ECBTC.sol";
import {Base58} from "./Base58.sol";
import {Utils} from "./Utils.sol";

/**
 * @title SerialLib - Serialization Library
 * @notice Takes care of serializing public keys, signatures and private keys.
 * @author https://github.com/nzmpi
 */
library SerialLib {
    using ECBTC for uint256;
    using Base58 for bytes;
    using Utils for bytes;
    using Utils for uint256;

    error BadData();

    /**
     * Serializes public key
     * @param _pubKey - The Public Key to be serialized
     * @param _isCompressed - If to return compressed public key or uncompressed
     * @return Serialized public key
     */
    function serializePublicKey(Point memory _pubKey, bool _isCompressed) internal pure returns (bytes memory) {
        if (_isCompressed) {
            // compressed SEC format
            if (_pubKey.y % 2 == 0) {
                return bytes.concat(bytes1(0x02), bytes32(_pubKey.x));
            } else {
                return bytes.concat(bytes1(0x03), bytes32(_pubKey.x));
            }
        } else {
            // uncompressed SEC format
            return bytes.concat(bytes1(0x04), bytes32(_pubKey.x), bytes32(_pubKey.y));
        }
    }

    /**
     * Deserializes public key
     * @param _data - The data to be deserialized
     * @return pubKey - The deserialized public key
     */
    function parsePublicKey(bytes memory _data) internal pure returns (Point memory pubKey) {
        if (_data.length == 0) revert BadData();
        bytes1 prefix = _data[0];
        if (prefix == 0x04) {
            if (_data.length != 65) revert BadData();
            assembly {
                // 33 = 32 + 1 = length slot + prefix byte
                mcopy(pubKey, add(_data, 33), 32)
                mcopy(add(pubKey, 32), add(_data, 65), 32)
            }
        } else if (prefix == 0x02 || prefix == 0x03) {
            if (_data.length != 33) revert BadData();
            assembly {
                mcopy(pubKey, add(_data, 33), 32)
            }
            pubKey.y = pubKey.x.deriveY(prefix);
        } else {
            revert BadData();
        }
    }

    /**
     * Serializes signature (DER format)
     * @param _sig - The signature to be serialized
     * @return res - The serialized signature
     */
    function serializeSignature(Signature memory _sig) internal pure returns (bytes memory res) {
        res = firstByteCheck(_sig.s.uint256ToBytes());
        // 0x02 - a marker
        res = bytes.concat(bytes1(0x02), bytes1(uint8(res.length)), res);
        bytes memory r = firstByteCheck(_sig.r.uint256ToBytes());
        res = bytes.concat(bytes1(0x02), bytes1(uint8(r.length)), r, res);
        // 0x30 - a marker
        res = bytes.concat(bytes1(0x30), bytes1(uint8(res.length)), res);
    }

    /**
     * Deserializes signature
     * @param _data - The data to be deserialized
     * @return sig - The deserialized signature
     */
    function parseSignature(bytes memory _data) internal pure returns (Signature memory sig) {
        if (_data.length < 8) revert BadData();
        if (_data[0] != 0x30 || _data[2] != 0x02) revert BadData();

        // r
        uint256 len = uint8(bytes1(_data[3]));
        bytes memory temp = new bytes(len);
        if (_data[4] == 0x00) {
            assembly {
                mstore(temp, sub(len, 1))
                // 37 = 32 + 5, we skip 2 markers, 2 length bytes and prepended 0x00
                mcopy(add(temp, 32), add(_data, 37), sub(len, 1))
            }
            sig.r = temp.bytesToUint256();
        } else {
            assembly {
                // 36 = 32 + 4, we skip 2 markers and 2 length bytes
                mcopy(add(temp, 32), add(_data, 36), len)
            }
            sig.r = temp.bytesToUint256();
        }

        // s
        if (_data[len + 4] != 0x02) revert BadData();
        len += 5;
        uint256 lenS = uint8(bytes1(_data[len]));
        ++len;
        if (_data[len] == 0x00) {
            assembly {
                mstore(temp, sub(lenS, 1))
                // 33 = 32 + 1, we skip prepended 0x00
                mcopy(add(temp, 32), add(_data, add(33, len)), sub(lenS, 1))
            }
            sig.s = temp.bytesToUint256();
        } else {
            assembly {
                mstore(temp, lenS)
                mcopy(add(temp, 32), add(_data, add(32, len)), lenS)
            }
            sig.s = temp.bytesToUint256();
        }
    }

    /**
     * Serializes private key (WIF format)
     * @param _privKey - The private key to be serialized
     * @param _isCompressed - Indicates whether the public key was compressed to derive the address
     * @return res - The serialized private key
     */
    function serializePrivateKey(uint256 _privKey, bool _isCompressed) internal pure returns (bytes memory res) {
        if (_isCompressed) {
            /// @dev for testnet change 0x80 -> 0xef
            res = bytes.concat(bytes1(0x80), bytes32(_privKey), bytes1(0x01));
            res = bytes.concat(res, bytes4(sha256(bytes.concat(sha256(res))))).encode();
        } else {
            /// @dev for testnet change 0x80 -> 0xef
            res = bytes.concat(bytes1(0x80), bytes32(_privKey));
            res = bytes.concat(res, bytes4(sha256(bytes.concat(sha256(res))))).encode();
        }
    }

    /**
     * Checks if the first byte is greater than 0x80
     * If it is, prepends 0x00
     * @param x - s or r from signature
     * @return The result
     */
    function firstByteCheck(bytes memory x) private pure returns (bytes memory) {
        return x[0] > 0x80 ? bytes.concat(bytes1(0x00), x) : x;
    }
}
