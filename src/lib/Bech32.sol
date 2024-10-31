// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Bech32 library
 * @notice Takes care of Bech32 encoding in Solidity
 * @dev https://medium.com/@meshcollider/some-of-the-math-behind-bech32-addresses-cf03c7496285
 * @dev https://github.com/sipa/bech32/blob/master/ref/javascript/bech32.js
 * @author https://github.com/nzmpi
 */
library Bech32 {
    bytes constant ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    bytes3 constant BC1 = 0x626331;
    bytes3 constant TB1 = 0x746231;
    bytes5 constant BC = 0x0303000203;
    bytes5 constant TB = 0x0303001402;

    error NotBech32();
    error WrongHashLength();
    error WrongAddressLength();

    /**
     * Encodes a hash to a Bech32 address
     * @param _hash - The hash to encode
     * @param _isMainnet - Whether the address is for the mainnet or not
     * @return res - The Bech32 address
     */
    function encode(bytes memory _hash, bool _isMainnet) internal pure returns (bytes memory res) {
        uint256 len = _hash.length;
        if (len == 20) {
            res = encode20(bytes20(_hash));
        } else if (len == 32) {
            res = encode32(bytes32(_hash));
        } else {
            revert WrongHashLength();
        }

        res = bytes.concat(res, getChecksum(res, _isMainnet));
        len = res.length;
        for (uint256 i; i < len; ++i) {
            res[i] = ALPHABET[uint8(res[i])];
        }
        res = bytes.concat(_isMainnet ? BC1 : TB1, res);
    }

    /**
     * Verifies a Bech32 address
     * @param _address - The address to verify
     * @return res - Whether the address is valid
     */
    function verifyChecksum(bytes memory _address) internal pure returns (bool) {
        bytes3 prefix = bytes3(_address);
        if (prefix != BC1 && prefix != TB1) return false;
        if (_address[3] != "q") return false;
        if (_address.length > 90) return false;

        return polyMod(bytes.concat(prefix == BC1 ? BC : TB, decode(_address))) == 1;
    }

    /**
     * Returns the Bech32 address hash
     * @param _address - The address to get the hash from
     * @return res - The hash
     */
    function getHash(bytes memory _address) internal pure returns (bytes memory res) {
        bytes3 prefix = bytes3(_address);
        if (prefix != BC1 && prefix != TB1) revert NotBech32();
        bytes memory temp = decode(_address);
        uint256 tempOffset = temp.length - 7;
        uint256 resOffset = 19;
        uint256 max = 4;
        if (tempOffset == 32) {
            res = new bytes(20);
        } else if (tempOffset == 52) {
            res = new bytes(32);
            res[31] = bytes1(uint8(temp[52] >> 4) + uint8(temp[51] << 1) + uint8((temp[50] & 0x03) << 6));
            res[30] = bytes1(uint8((temp[50] & 0x1c) >> 2) + uint8(temp[49] << 3));
            tempOffset = 48;
            max = 6;
            resOffset = 29;
        } else {
            revert WrongAddressLength();
        }

        for (uint256 i; i < max; ++i) {
            res[resOffset - 5 * i] =
                bytes1(uint8(temp[tempOffset - 8 * i]) + uint8((temp[tempOffset - 1 - 8 * i] & 0x07) << 5));
            res[resOffset - 1 - 5 * i] = bytes1(
                uint8((temp[tempOffset - 1 - 8 * i] & 0x18) >> 3) + uint8(temp[tempOffset - 2 - 8 * i] << 2)
                    + uint8((temp[tempOffset - 3 - 8 * i] & 0x01) << 7)
            );
            res[resOffset - 2 - 5 * i] = bytes1(
                uint8((temp[tempOffset - 3 - 8 * i] & 0x1e) >> 1) + uint8((temp[tempOffset - 4 - 8 * i] & 0x0f) << 4)
            );
            res[resOffset - 3 - 5 * i] = bytes1(
                uint8((temp[tempOffset - 4 - 8 * i] & 0x10) >> 4) + uint8(temp[tempOffset - 5 - 8 * i] << 1)
                    + uint8((temp[tempOffset - 6 - 8 * i] & 0x03) << 6)
            );
            res[resOffset - 4 - 5 * i] =
                bytes1(uint8((temp[tempOffset - 6 - 8 * i] & 0x1c) >> 2) + uint8(temp[tempOffset - 7 - 8 * i] << 3));
        }
    }

    /**
     * Encodes a 20-byte hash
     * @param _hash - The hash to encode
     * @return res - The encoded hash
     */
    function encode20(bytes20 _hash) private pure returns (bytes memory res) {
        uint256 value = uint160(_hash);
        res = new bytes(33);
        for (uint256 i; i < 32; ++i) {
            res[32 - i] = bytes1(uint8(value >> (5 * i) & 0x1f));
        }
    }

    /**
     * Encodes a 32-byte hash
     * @param _hash - The hash to encode
     * @return res - The encoded hash
     */
    function encode32(bytes32 _hash) private pure returns (bytes memory res) {
        uint256 value = uint256(_hash);
        res = new bytes(53);
        res[52] = bytes1(uint8((value & 1) << 4));
        value >>= 1;
        for (uint256 i; i < 52; ++i) {
            res[51 - i] = bytes1(uint8(value >> (5 * i) & 0x1f));
        }
    }

    /**
     * Decodes a Bech32 address
     * @param _address - The address to decode
     * @return res - The decoded address
     */
    function decode(bytes memory _address) private pure returns (bytes memory res) {
        uint256 len = _address.length;
        res = new bytes(len - 3);
        for (uint256 i = 3; i < len; ++i) {
            res[i - 3] = getIndex(_address[i]);
        }
    }

    /**
     * Returns the checksum
     * @param _data - The data to checksum
     * @param _isMainnet - Whether the address is a mainnet address or not
     * @return res - The checksum
     */
    function getChecksum(bytes memory _data, bool _isMainnet) private pure returns (bytes6) {
        _data = bytes.concat(_isMainnet ? BC : TB, _data, bytes6(0));
        uint256 mod = polyMod(_data) ^ 1;
        for (uint256 i; i < 6; ++i) {
            _data[i] = bytes1(uint8((mod >> 5 * (5 - i)) & 0x1f));
        }

        return bytes6(_data);
    }

    /**
     * Polynomial modulus
     * @param _data - Input data
     * @return chk - Result
     */
    function polyMod(bytes memory _data) private pure returns (uint256 chk) {
        uint256[5] memory generator = [uint256(0x3b6a57b2), 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        chk = 1;
        uint256 len = _data.length;
        uint256 temp;
        for (uint256 i; i < len; ++i) {
            temp = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ uint8(_data[i]);
            for (uint256 j; j < 5; ++j) {
                if ((temp >> j) & 1 == 1) {
                    chk ^= generator[j];
                }
            }
        }
    }

    /**
     * Returns the index of a character
     * @param _char - The character to get the index of
     * @return res - The index
     */
    function getIndex(bytes1 _char) private pure returns (bytes1) {
        for (uint256 i; i < 32; ++i) {
            if (ALPHABET[i] == _char) {
                return bytes1(uint8(i));
            }
        }
        revert NotBech32();
    }
}
