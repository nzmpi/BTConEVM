// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Base58 library
 * @notice Takes care of Base58 encoding in Solidity
 * @author https://github.com/nzmpi 
 */
library Base58 {
    // no 0, O, I and l
    bytes constant ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    error EmptyData();

    /**
     * Encode data to Base58
     * @param _data - The data to encode
     * @return res - The encoded data in Base58
     */
    function encode(bytes memory _data) internal pure returns (bytes memory res) {
        uint256 len = _data.length;
        if (len == 0) revert EmptyData();
        // count leading zeros
        uint256 zeros;
        while (zeros < len && _data[zeros] == 0) {
            ++zeros;
        }

        // log(256)/log(58) = 1.36565823731...
        uint256 tempLen = zeros + ((len - zeros) * 136565823731) / 100000000000 + 1;
        bytes memory temp = new bytes(tempLen);
        uint256 carry;
        uint256 ptr;
        uint256 high = tempLen - 1;
        // encode
        for (uint256 i; i < len; ++i) {
            ptr = tempLen - 1;
            carry = uint8(_data[i]);
            while (ptr > high || carry != 0) {
                carry += uint256(uint8(temp[ptr])) << 8;
                temp[ptr] = bytes1(uint8(carry % 58));
                carry /= 58;
                if (ptr == 0) break;
                --ptr;
            }
            high = ptr;
        }

        // check for more leading zeros
        uint256 delta = zeros;
        while (delta < tempLen && temp[delta] == 0) {
            ++delta;
        }
        delta -= zeros;
        tempLen -= delta;

        res = new bytes(tempLen);
        uint256 j;
        // replace elements with corresponding characters
        for (uint256 i; i < tempLen; ++i) {
            j = i + delta;
            res[i] = ALPHABET[uint8(temp[j])];
        }
    }

    /**
     * Checksum data
     * @param _data - The data to checksum
     * @return res - The checksum
     */ 
    function checksum(bytes memory _data) internal pure returns (bytes memory res) {
        /// @dev for testnet change 0x00 -> 0x6f
        bytes memory temp = bytes.concat(bytes1(0x00), ripemd160(bytes.concat(sha256(_data))));
        res = encode(bytes.concat(temp, bytes4(sha256(bytes.concat(sha256(temp))))));
    }
}
