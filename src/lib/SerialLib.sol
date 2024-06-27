// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Structs.sol";
import {ECBTC} from "./ECBTC.sol";
import {Base58} from "./Base58.sol";
import {Utils} from "./Utils.sol";
import {Varint} from "./Varint.sol";

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
    using Varint for uint256;
    using Varint for bytes;

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
     * Serializes transaction
     * @param _tx - The transaction to be serialized
     * @return res - The serialized transaction
     */
    function serializeTransaction(Transaction memory _tx) internal pure returns (bytes memory res) {
        res = bytes.concat(_tx.version).convertEndian();
        uint256 len = _tx.inputs.length;
        if (len == 0) revert BadData();
        res = bytes.concat(res, len.toVarint());
        for (uint256 i; i < len; ++i) {
            res = bytes.concat(
                res,
                bytes.concat(_tx.inputs[i].txId).convertEndian(),
                bytes.concat(_tx.inputs[i].vout).convertEndian(),
                _tx.inputs[i].scriptSig,
                bytes.concat(_tx.inputs[i].sequence).convertEndian()
            );
        }

        len = _tx.outputs.length;
        if (len == 0) revert BadData();
        res = bytes.concat(res, len.toVarint());
        for (uint256 i; i < len; ++i) {
            res = bytes.concat(res, bytes.concat(_tx.outputs[i].amount).convertEndian(), _tx.outputs[i].scriptPubKey);
        }

        res = bytes.concat(res, bytes.concat(_tx.locktime).convertEndian());
    }

    /**
     * Parses transaction
     * @param _data - The data to be parsed
     * @return res - The parsed transaction
     */
    function parseTransaction(bytes memory _data) internal pure returns (Transaction memory res) {
        res.version = bytes4(_data.readFromMemory(0, 4).convertEndian());
        (uint256 len, uint256 ptr) = _data.fromVarint(4);
        if (len == 0) revert BadData();

        res.inputs = new TxInput[](len);
        uint256 lenScript;
        uint256 ptrScript;
        for (uint256 i; i < len; ++i) {
            res.inputs[i].txId = bytes32(_data.readFromMemory(ptr, 32).convertEndian());
            res.inputs[i].vout = bytes4(_data.readFromMemory(ptr + 32, 4).convertEndian());
            ptr += 36;
            (lenScript, ptrScript) = _data.fromVarint(ptr);
            res.inputs[i].scriptSig = _data.readFromMemory(ptr, lenScript + ptrScript - ptr);
            ptr = ptrScript + lenScript;
            res.inputs[i].sequence = bytes4(_data.readFromMemory(ptr, 4).convertEndian());
            ptr += 4;
        }

        (len, ptr) = _data.fromVarint(ptr);
        res.outputs = new TxOutput[](len);
        for (uint256 i; i < len; ++i) {
            res.outputs[i].amount = bytes8(_data.readFromMemory(ptr, 8).convertEndian());
            ptr += 8;
            (lenScript, ptrScript) = _data.fromVarint(ptr);
            res.outputs[i].scriptPubKey = _data.readFromMemory(ptr, lenScript + ptrScript - ptr);
            ptr = ptrScript + lenScript;
        }

        res.locktime = bytes4(_data.readFromMemory(ptr, 4).convertEndian());
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
