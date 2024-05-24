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
        if (_x < 253) {
            return bytes.concat(bytes1(uint8(_x)));
        } else if (_x < 65535) {
            bytes memory littleEndian = bytes.concat(bytes2(uint16(_x))).convertEndian();
            return bytes.concat(hex"fd", littleEndian);
        } else if (_x < 4294967295) {
            bytes memory littleEndian = bytes.concat(bytes4(uint32(_x))).convertEndian();
            return bytes.concat(hex"fe", littleEndian);
        } else if (_x < 18446744073709551615) {
            bytes memory littleEndian = bytes.concat(bytes8(uint64(_x))).convertEndian();
            return bytes.concat(hex"ff", littleEndian);
        } else {
            revert VarintOverflow();
        }
    }

    /**
     * Converts varint to uint256
     * @param _data - The varint to convert
     * @return res - The converted uint256
     */
    function fromVarint(bytes memory _data) internal pure returns (uint256) {
        uint256 len = _data.length;
        if (len == 1) {
            return uint256(uint8(_data[0]));
        } else if (len == 3 || len == 5 || len == 9) {
            --len;
            bytes memory bigEndian = new bytes(len);
            assembly {
                mcopy(add(bigEndian, 0x20), add(_data, 0x21), len)
            }
            if (len == 2) return uint16(bytes2(bigEndian.convertEndian()));
            else if (len == 4) return uint32(bytes4(bigEndian.convertEndian()));
            else return uint64(bytes8(bigEndian.convertEndian()));
        } else {
            revert NotVarint();
        }
    }
}
