// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./lib/Utils.sol";
import {SerialLib} from "./lib/SerialLib.sol";
import {SigLib} from "./lib/SigLib.sol";
import {Utils} from "./lib/Utils.sol";
import {Varint} from "./lib/Varint.sol";

/**
 * @title Script
 * @notice Emulates the Script language
 * @author https://github.com/nzmpi
 */
contract Script {
    using Utils for bytes;
    using Utils for uint256;
    using SerialLib for bytes;
    using SigLib for uint256;
    using Varint for bytes;

    bytes[] stack;
    mapping(bytes32 opcode => function(bytes calldata, uint256) returns (uint256)) opcodes;

    error StackIsEmpty();
    error InvalidScript();

    modifier checkStack() {
        if (stack.length == 0) revert StackIsEmpty();
        _;
    }

    modifier checkStack2() {
        if (stack.length < 2) revert StackIsEmpty();
        _;
    }

    constructor() payable {
        opcodes[hex"00"] = op_0;
        opcodes[hex"4c"] = op_pushdata1;
        opcodes[hex"4d"] = op_pushdata2;
        opcodes[hex"4e"] = op_pushdata4;
        opcodes[hex"51"] = op_1;
        opcodes[hex"52"] = op_2;
        opcodes[hex"69"] = op_verify;
        opcodes[hex"75"] = op_drop;
        opcodes[hex"76"] = op_dup;
        opcodes[hex"7c"] = op_swap;
        opcodes[hex"87"] = op_equal;
        opcodes[hex"88"] = op_equalverify;
        opcodes[hex"91"] = op_not;
        opcodes[hex"93"] = op_add;
        opcodes[hex"94"] = op_sub;
        opcodes[hex"a9"] = op_hash160;
        opcodes[hex"aa"] = op_hash256;
        opcodes[hex"ac"] = op_checksig;
    }

    /**
     * Executes the script
     * @param script - ScriptSig + ScriptPubKey
     */
    function execute(bytes calldata script) external {
        uint256 len = script.length;
        if (len == 0) revert InvalidScript();
        // an opcode or data length
        bytes32 op = script[0];
        // the pointer
        uint256 ptr;
        if (op == 0) {
            revert InvalidScript();
        } else if (op == hex"fd") {
            len = bytes(script[0:3]).fromVarint();
            ptr = 3;
        } else if (op == hex"fe") {
            len = bytes(script[0:5]).fromVarint();
            ptr = 5;
        } else if (op == hex"ff") {
            len = bytes(script[0:9]).fromVarint();
            ptr = 9;
        } else {
            len = uint8(bytes1(op));
            ptr = 1;
        }
        // we read the script byte by byte until we reach the end
        while (ptr <= len) {
            op = script[ptr];
            if (op > 0 && op < hex"4c") {
                ptr = op_pushdata1(script, --ptr);
            } else {
                ptr = opcodes[op](script, ptr);
            }
        }

        if (stack.length == 0 || stack[stack.length - 1].length == 0) revert InvalidScript();
    }

    /**
     * An empty array of bytes is pushed to the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_0(bytes calldata, uint256 _ptr) internal returns (uint256) {
        stack.push(hex"");
        return ++_ptr;
    }

    /**
     * Reads the next byte and pushes that amount of bytes to the stack
     * @dev The length is in little endian
     * @param _data - The script data
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_pushdata1(bytes calldata _data, uint256 _ptr) internal returns (uint256) {
        ++_ptr;
        uint256 len = uint8(bytes1(_data[_ptr]));
        ++_ptr;
        stack.push(_data[_ptr:_ptr + len]);
        return _ptr + len;
    }

    /**
     * Reads the next 2 bytes and pushes that amount of bytes to the stack
     * @dev The length is in little endian
     * @param _data - The script data
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_pushdata2(bytes calldata _data, uint256 _ptr) internal returns (uint256) {
        ++_ptr;
        uint256 len = uint16(bytes2(bytes(_data[_ptr:_ptr + 2]).convertEndian()));
        // max length is 520 bytes
        if (len > 520) revert InvalidScript();
        _ptr += 2;
        stack.push(_data[_ptr:_ptr + len]);
        return _ptr + len;
    }

    /**
     * Reads the next 4 bytes and pushes that amount of bytes to the stack
     * @dev The length is in little endian
     * @param _data - The script data
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_pushdata4(bytes calldata _data, uint256 _ptr) internal returns (uint256) {
        ++_ptr;
        uint256 len = uint32(bytes4(bytes(_data[_ptr:_ptr + 4]).convertEndian()));
        // max length is 520 bytes
        if (len > 520) revert InvalidScript();
        _ptr += 4;
        stack.push(_data[_ptr:_ptr + len]);
        return _ptr + len;
    }

    /**
     * Pushes 1 to the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_1(bytes calldata, uint256 _ptr) internal returns (uint256) {
        stack.push(hex"01");
        return ++_ptr;
    }

    /**
     * Pushes 2 to the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_2(bytes calldata, uint256 _ptr) internal returns (uint256) {
        stack.push(hex"02");
        return ++_ptr;
    }

    /**
     * Verifies that the top of the stack is 1
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_verify(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        if (keccak256(stack[stack.length - 1]) != keccak256(hex"01")) revert InvalidScript();
        stack.pop();
        return ++_ptr;
    }

    /**
     * Removes the top of the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_drop(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        stack.pop();
        return ++_ptr;
    }

    /**
     * Duplicates the top of the stack and pushes it to the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_dup(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        stack.push(stack[stack.length - 1]);
        return ++_ptr;
    }

    /**
     * Swaps the top two elements of the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_swap(bytes calldata, uint256 _ptr) internal checkStack2 returns (uint256) {
        uint256 len = stack.length - 1;
        bytes memory temp = stack[len];
        stack[len] = stack[len - 1];
        stack[len - 1] = temp;
        return ++_ptr;
    }

    /**
     * Compares the top two elements of the stack and pushes 1 if they are equal and 0 otherwise
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_equal(bytes calldata, uint256 _ptr) internal checkStack2 returns (uint256) {
        uint256 len = stack.length;
        if (keccak256(stack[len - 1]) == keccak256(stack[len - 2])) {
            stack.pop();
            stack[len - 2] = hex"01";
        } else {
            stack.pop();
            stack[len - 2] = hex"";
        }
        return ++_ptr;
    }

    /**
     * Compares the top two elements of the stack and reverts if they are not equal
     * @dev This is equivalent to calling op_equal and then op_verify
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_equalverify(bytes calldata, uint256 _ptr) internal checkStack2 returns (uint256) {
        uint256 len = stack.length;
        if (keccak256(stack[len - 1]) == keccak256(stack[len - 2])) {
            stack.pop();
            stack.pop();
        } else {
            revert InvalidScript();
        }
        return ++_ptr;
    }

    /**
     * If the top of the stack is 0, pushes 1, otherwise pushes 0
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_not(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        uint256 len = stack.length;
        stack[len - 1] = keccak256(stack[len - 1]) == keccak256(hex"") ? bytes(hex"01") : bytes(hex"");
        return ++_ptr;
    }

    /**
     * Adds the top two elements of the stack and pushes the result to the stack
     * @dev The numbers are limited to signed 32-bit integers
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_add(bytes calldata, uint256 _ptr) internal checkStack2 returns (uint256) {
        int256 a = _getNumber();
        int256 b = _getNumber();

        // overflow is allowed
        unchecked {
            a = (a + b) % type(int32).max;
        }
        _pushNumber(a);
        return ++_ptr;
    }

    /**
     * Subtracts the top two elements of the stack and pushes the result to the stack
     * @dev The numbers are limited to signed 32-bit integers
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_sub(bytes calldata, uint256 _ptr) internal checkStack2 returns (uint256) {
        int256 a = _getNumber();
        int256 b = _getNumber();

        // overflow is allowed
        unchecked {
            a = (a - b) % type(int32).max;
        }
        _pushNumber(a);
        return ++_ptr;
    }

    /**
     * Hashes the top element of the stack and pushes the result to the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_hash160(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        uint256 len = stack.length - 1;
        stack[len] = bytes.concat(stack[len].hash160());
        return ++_ptr;
    }

    /**
     * Hashes the top element of the stack and pushes the result to the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_hash256(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        uint256 len = stack.length - 1;
        stack[len] = bytes.concat(stack[len].hash256());
        return ++_ptr;
    }

    /**
     * Verifis that the signature for a tx input is valid
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_checksig(bytes calldata, uint256 _ptr) internal checkStack2 returns (uint256) {
        uint256 len = stack.length - 1;
        // TODO
        uint256 messageHash;
        bytes memory pubKey = stack[len];
        --len;
        bytes memory sig = stack[len];
        stack.pop();
        if (messageHash.verify(sig.parseSignature(), pubKey.parsePublicKey())) {
            stack[len] = hex"01";
        } else {
            stack[len] = hex"";
        }
        return ++_ptr;
    }

    /**
     * Gets the number from the top of the stack
     * @dev The number is limited to signed 32-bit integers and is in little-endian
     * @return res - The number
     */
    function _getNumber() private returns (int256 res) {
        bytes memory num = stack[stack.length - 1].convertEndian();
        stack.pop();
        if (num.length == 0) return 0;

        bool isNegative;
        // check if the highest bit is set to 1
        // if it is, the number is negative
        if (num[0] & 0x80 == 0x80) {
            isNegative = true;
            // remove the highest bit
            num[0] = num[0] & 0x7f;
        }

        res = isNegative ? -int256(num.bytesToUint256()) : int256(num.bytesToUint256());
        if (res > type(int32).max || res < type(int32).min) revert InvalidScript();
    }

    /**
     * Pushes the number to the stack
     * @dev The number is limited to signed 32-bit integers and is in little-endian
     * @param _num - The number
     */
    function _pushNumber(int256 _num) private {
        if (_num > type(int32).max || _num < type(int32).min) {
            revert InvalidScript();
        } else if (_num == 0) {
            stack.push(hex"");
            return;
        }

        bytes memory num;
        if (_num < 0) {
            num = uint256(-_num).uint256ToBytes().convertEndian();
            // if the highest bit is already set to 1,
            // add a byte with the highest bit set to 1
            if (num[num.length - 1] & 0x80 == 0x80) {
                num = bytes.concat(num, hex"80");
            } else {
                num[num.length - 1] = num[num.length - 1] | 0x80;
            }
        } else {
            num = uint256(_num).uint256ToBytes().convertEndian();
            // if the highest bit is already set to 1,
            // add a byte with the highest bit set to 0
            if (num[num.length - 1] & 0x80 == 0x80) {
                num = bytes.concat(num, hex"00");
            }
        }

        stack.push(num);
    }
}
