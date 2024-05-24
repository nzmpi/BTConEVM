// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Utils library
 * @notice Some helper functions
 * @author https://github.com/nzmpi
 */
library Utils {
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
}
