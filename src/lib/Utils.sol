// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Utils library
 * @notice Some helper functions
 * @author https://github.com/nzmpi
 */
library Utils {
    error WrongLength();

    /**
     * Hash160
     * @param _data - The data to hash
     * @return res - Hashed data
     */
    function hash160(bytes memory _data) internal pure returns (bytes32) {
        return ripemd160(bytes.concat(sha256(_data)));
    }

    /**
     * Hash256
     * @param _data - The data to hash
     * @return res - Hashed data
     */
    function hash256(bytes memory _data) internal pure returns (bytes32) {
        return sha256(bytes.concat(sha256(_data)));
    }

    /**
     * Converts the endianness of the data
     * @param _data - The data to convert
     * @return res - Converted data
     */
    function convertEndian(bytes memory _data) internal pure returns (bytes memory res) {
        uint256 len = _data.length;
        if (len < 2) return _data;
        res = new bytes(len);
        for (uint256 i; i < len; ++i) {
            res[i] = _data[len - 1 - i];
        }
    }

    /**
     * Converts bytes to uint256
     * @dev Reverts if length is greater than 32
     * @param _data - The data to be converted
     * @return res - The converted data
     */
    function bytesToUint256(bytes memory _data) internal pure returns (uint256 res) {
        uint256 len = _data.length;
        if (len == 0 || len > 32) revert WrongLength();

        // padding zeros
        bytes memory temp = new bytes(32);
        for (uint256 i; i < len; ++i) {
            temp[i + 32 - len] = _data[i];
        }

        return uint256(bytes32(temp));
    }

    /**
     * Converts uint256 to bytes
     * @param _data - The data to be converted
     * @return res - The converted data
     */
    function uint256ToBytes(uint256 _data) internal pure returns (bytes memory res) {
        res = bytes.concat(bytes32(_data));

        // counting leading zeroes
        uint256 zeroes;
        for (uint256 i; i < 32; ++i) {
            if (res[i] == 0x00) {
                ++zeroes;
            } else {
                break;
            }
        }
        uint256 len = 32 - zeroes;
        assembly {
            mstore(res, len)
            let start := add(res, 32)
            mcopy(start, add(start, zeroes), len)
        }
    }
}
