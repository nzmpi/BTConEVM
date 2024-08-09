// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Utils.sol";

/**
 * @title Varint
 * @notice Takes care of Varint encoding in Solidity
 * @author https://github.com/nzmpi
 */
library Varint {
    using Utils for bytes;

    error VarintOverflow();
    error NotVarint();

    /**
     * Converts uint256 to varint
     * @param _x - The uint256 to convert
     * @return res - The converted varint
     */
    function toVarint(uint256 _x) internal pure returns (bytes memory) {
        if (_x <= type(uint8).max - 3) {
            return bytes.concat(bytes1(uint8(_x)));
        } else if (_x <= type(uint16).max) {
            bytes memory littleEndian = bytes.concat(bytes2(uint16(_x))).convertEndian();
            return bytes.concat(hex"fd", littleEndian);
        } else if (_x <= type(uint32).max) {
            bytes memory littleEndian = bytes.concat(bytes4(uint32(_x))).convertEndian();
            return bytes.concat(hex"fe", littleEndian);
        } else if (_x <= type(uint64).max) {
            bytes memory littleEndian = bytes.concat(bytes8(uint64(_x))).convertEndian();
            return bytes.concat(hex"ff", littleEndian);
        } else {
            revert VarintOverflow();
        }
    }

    /**
     * Converts varint to uint256 from a given data of variable length
     * @param _data - The data that contains the varint
     * @param _offset - The offset in data where the varint itself starts
     * @return num - The converted uint256
     * @return offset - The updated offset
     */
    function fromVarint(bytes memory _data, uint256 _offset) internal pure returns (uint256 num, uint256 offset) {
        if (_data.length == 0) revert NotVarint();
        num = uint8(_data[_offset]);
        offset = _offset + 1;
        if (num < 0xfd) {
            return (num, offset);
        } else if (num == 0xfd) {
            num = uint16(bytes2(_data.readFromMemory(offset, 2).convertEndian()));
            offset += 2;
        } else if (num == 0xfe) {
            num = uint32(bytes4(_data.readFromMemory(offset, 4).convertEndian()));
            offset += 4;
        } else if (num == 0xff) {
            num = uint64(bytes8(_data.readFromMemory(offset, 8).convertEndian()));
            offset += 8;
        }
    }
}
