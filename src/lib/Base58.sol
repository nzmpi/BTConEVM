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

    error WrongData();
    error NotBase58();

    /**
     * Encode data from hex to Base58
     * @param _data - The data to encode in hex
     * @return res - The encoded data in Base58
     */
    function encode(bytes memory _data) internal pure returns (bytes memory res) {
        uint256 len = _data.length;
        if (len == 0) revert WrongData();
        // count leading zeroes
        uint256 zeroes;
        while (zeroes < len && _data[zeroes] == 0) {
            ++zeroes;
        }

        // log(256)/log(58) = 1.36565823731...
        uint256 tempLen = zeroes + ((len - zeroes) * 136565823731) / 100000000000 + 1;
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

        // check for more leading zeroes
        carry = zeroes;
        while (carry < tempLen && temp[carry] == 0) {
            ++carry;
        }
        carry -= zeroes;
        tempLen -= carry;

        res = new bytes(tempLen);
        for (uint256 i; i < tempLen; ++i) {
            res[i] = ALPHABET[uint8(temp[i + carry])];
        }
    }

    /**
     * Decode data from Base58 to hex
     * @param _data - The data to decode in Base58
     * @return res - The decoded data in hex
     */
    function decode(bytes memory _data) internal pure returns (bytes memory res) {
        uint256 len = _data.length;
        if (len == 0) revert WrongData();

        // an array of uint256 to store the decoded data
        uint256 tempLen = (len + 2) / 3;
        uint256[] memory temp = new uint256[](tempLen);
        bytes1 char;
        uint256 index;
        uint256 ptr;
        uint256 value;
        for (uint256 i; i < len; ++i) {
            char = _data[i];
            index = getIndex(char);
            ptr = tempLen - 1;
            while (true) {
                value = temp[ptr] * 58 + index;
                temp[ptr] = uint32(value);
                index = value >> 32;
                if (ptr == 0) break;
                --ptr;
            }
        }

        index = len % 4;
        if (index == 0) {
            index = 24;
        } else {
            index = (index - 1) * 8;
        }

        res = new bytes(2 * (((len * 136565823731) / 100000000000) + 1));
        uint256 resLen;
        for (uint256 i; i < tempLen; ++i) {
            while (true) {
                res[resLen] = bytes1(uint8(temp[i] >> index));
                ++resLen;
                if (index < 8) break;
                index -= 8;
            }
            index = 24;
        }

        // count leading zeroes in _data
        value = 0;
        // 0x31 == encode(0)
        while (value < len && _data[value] == 0x31) {
            ++value;
        }

        // count leading zeroes in res
        index = value;
        while (index < resLen && res[index] == 0) {
            ++index;
        }
        index -= value;
        resLen -= index;
        assembly {
            let start := add(res, 0x20)
            mcopy(start, add(start, index), resLen)
            mstore(res, resLen)
        }
    }

    /**
     * Finds the index of a character in ALPHABET
     * @dev Reverts if character is not in ALPHABET
     * @param _char - The character in Base58
     */
    function getIndex(bytes1 _char) private pure returns (uint256) {
        uint256 len = ALPHABET.length;
        for (uint256 i; i < len; ++i) {
            if (ALPHABET[i] == _char) {
                return i;
            }
        }
        revert NotBase58();
    }
}
