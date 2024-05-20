// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Point, Signature} from "./Structs.sol";
import {ECBTC} from "./ECBTC.sol";
import {Base58} from "./Base58.sol";

/**
 * @title SerialLib - Serialization Library
 * @notice Takes care of serializing public keys, signatures and private keys.
 * @author https://github.com/nzmpi
 */
library SerialLib {
    using ECBTC for uint256;
    using Base58 for bytes;

    error WrongPrefix();

    /**
     * Serializes public key
     * @param _pubKey - The Public Key to be serialized
     * @param _isCompressed - If to return compressed public key or uncompressed
     * @return - Serialized public key
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
        bytes1 prefix = _data[0];
        if (prefix == 0x04) {
            require(_data.length == 65, "Wrong data length");
            assembly {
                // 33 = 32 + 1 = length slot + prefix
                mcopy(pubKey, add(_data, 33), 32)
                mcopy(add(pubKey, 32), add(_data, 65), 32)
            }
        } else if (prefix == 0x02 || prefix == 0x03) {
            require(_data.length == 33, "Wrong data length");
            assembly {
                mcopy(pubKey, add(_data, 33), 32)
            }
            pubKey.y = pubKey.x.deriveY(prefix);
        } else {
            revert WrongPrefix();
        }
    }

    /**
     * Serializes signature (DER format)
     * @param _sig - The signature to be serialized
     * @return res - Serialized signature
     */
    function serializeSignature(Signature memory _sig) internal pure returns (bytes memory res) {
        bytes memory s = firstByteCheck(bytes32(_sig.s));
        // 0x02 - a marker
        res = bytes.concat(bytes1(0x02), bytes1(uint8(s.length)), s);
        bytes memory r = firstByteCheck(bytes32(_sig.r));
        res = bytes.concat(bytes1(0x02), bytes1(uint8(r.length)), r, res);
        // 0x30 - a marker
        res = bytes.concat(bytes1(0x30), bytes1(uint8(res.length)), res);
    }

    /**
     * Serializes private key (WIF format)
     * @param _privKey - The private key to be serialized
     * @param _isCompressed - Indicates whether the public key was compressed to derive the address
     * @return res - Serialized private key
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
     */
    function firstByteCheck(bytes32 x) private pure returns (bytes memory) {
        return bytes1(x) > 0x80 ? bytes.concat(bytes1(0x00), bytes32(x)) : bytes.concat(bytes32(x));
    }
}
