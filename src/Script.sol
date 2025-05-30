// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SerialLib} from "./lib/SerialLib.sol";
import {SigLib} from "./lib/SigLib.sol";
import "./lib/Utils.sol";
import {Varint} from "./lib/Varint.sol";

/**
 * @title Script
 * @notice Emulates the Script language
 * @author https://github.com/nzmpi
 */
contract Script {
    using SerialLib for bytes;
    using SigLib for uint256;
    using Utils for *;
    using Varint for *;

    bytes32 constant KECCAK_01 = keccak256(hex"01");
    uint256 _signatureHash;
    bytes[] stack;
    mapping(bytes32 opcode => function(bytes calldata, uint256) returns (uint256)) opcodes;

    error BadNumber();
    error InvalidScript();
    error MaxLengthPushdata(uint256 length);
    error OP_EqualVerifyFailed();
    error OP_CheckMultisigFailed();
    error OP_VerifyFailed();
    error ScriptIsEmpty();
    error ScriptFailed();
    error StackIsEmpty();
    error WrongRedeemScriptHash();
    error WrongWitnessScriptHash();

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
        opcodes[hex"ae"] = op_checkmultisig;
    }

    /**
     * Executes the script
     * @param script - ScriptSig + ScriptPubKey
     * @param signatureHash - Signature hash
     * @param witness - Witness
     */
    function execute(bytes calldata script, bytes32 signatureHash, bytes[] calldata witness) external {
        uint256 len = script.length;
        if (len == 0) revert ScriptIsEmpty();
        // the pointer
        uint256 ptr;
        (len, ptr) = script.fromVarint(ptr);
        if (len == 0) revert ScriptIsEmpty();
        _signatureHash = uint256(signatureHash);
        // an opcode
        bytes32 op;
        // we read the script byte by byte until we reach the end
        while (ptr <= len) {
            op = script[ptr];
            if (op > 0 && op < hex"4c") {
                ptr = op_pushdata1(script, --ptr);
            } else if (op > hex"50" && op < hex"61") {
                ptr = op_n(op, script, ptr);
            } else if (
                // check if BIP0016
                op == hex"a9" && script.length == ptr + 23 // 20 bytes of hash + 2 opcodes + 1 length
                    && script[ptr + 1] == hex"14" // length of hash
                    && script[ptr + 22] == hex"87"
            ) {
                if (stack[stack.length - 1].hash160() != bytes20(script[ptr + 2:ptr + 22])) {
                    revert WrongRedeemScriptHash();
                }
                len = ptr - 1;
                ptr -= stack[stack.length - 1].length;
                stack.pop();
            } else if (
                // check if P2WPKH
                op == hex"00" && len == ptr + 21 && script[ptr + 1] == hex"14"
            ) {
                stack.push(witness[0]); // signature
                stack.push(witness[1]); // public key
                op_dup(script, ptr);
                op_hash160(script, ptr);
                stack.push(script[ptr + 2:ptr + 22]);
                op_equalverify(script, ptr);
                op_checksig(script, ptr);
                break;
            } else if (
                // check if P2WSH
                op == hex"00" && len == ptr + 33 && script[ptr + 1] == hex"20"
            ) {
                uint256 m = witness.length - 1;
                if (sha256(witness[m]) != bytes32(script[ptr + 2:ptr + 34])) revert WrongWitnessScriptHash();
                for (uint256 i; i < m; ++i) {
                    stack.push(witness[i]); // signatures
                }
                this.execute(bytes.concat(witness[m].length.toVarint(), witness[m]), signatureHash, witness);
                // we don't break here, because we don't want to continue the script
                return;
            } else {
                ptr = opcodes[op](script, ptr);
            }
        }
        if (stack.length == 0 || stack[stack.length - 1].length == 0) revert ScriptFailed();

        // clear the stack
        assembly {
            sstore(stack.slot, 0)
        }
    }

    /**
     * An empty array of bytes is pushed to the stack
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_0(bytes calldata, uint256 _ptr) internal returns (uint256) {
        stack.push("");
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
        if (len > 520) revert MaxLengthPushdata(len);
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
        if (len > 520) revert MaxLengthPushdata(len);
        _ptr += 4;
        stack.push(_data[_ptr:_ptr + len]);
        return _ptr + len;
    }

    /**
     * Pushes n to the stack, where 0 < n < 17
     * @param _op - The opcode
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_n(bytes32 _op, bytes calldata, uint256 _ptr) internal returns (uint256) {
        stack.push((uint256(_op >> 248) - 0x50).uint256ToBytes());
        return ++_ptr;
    }

    /**
     * Verifies that the top of the stack is 1
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_verify(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        if (keccak256(stack[stack.length - 1]) != KECCAK_01) revert OP_VerifyFailed();
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
            stack[len - 2] = "";
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
            revert OP_EqualVerifyFailed();
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
        stack[len - 1] = stack[len - 1].length == 0 ? bytes(hex"01") : bytes("");
        return ++_ptr;
    }

    /**
     * Adds the top two elements of the stack and pushes the result to the stack
     * @dev The numbers are limited to signed 32-bit integers
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_add(bytes calldata, uint256 _ptr) internal checkStack2 returns (uint256) {
        int32 a = _getNumber();
        int32 b = _getNumber();

        // overflow is allowed
        unchecked {
            a += b;
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
        int32 a = _getNumber();
        int32 b = _getNumber();

        // overflow is allowed
        unchecked {
            a -= b;
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
        bytes memory pubKey = stack[len];
        bytes memory sig = stack[--len];
        stack.pop();
        if (_signatureHash.verify(sig, pubKey)) {
            stack[len] = hex"01";
        } else {
            stack[len] = "";
        }
        return ++_ptr;
    }

    /**
     * Multisig verification
     * @param _ptr - The pointer
     * @return _ptr - The updated pointer
     */
    function op_checkmultisig(bytes calldata, uint256 _ptr) internal checkStack returns (uint256) {
        // number of public keys
        int256 temp = _getNumber();
        // at least 1 public key
        if (temp < 1) revert OP_CheckMultisigFailed();
        uint256 pubKeyLen = uint256(temp);
        // minus op_0
        uint256 index = stack.length - 1;
        // stack at least should have pubKeyLen amount of items
        if (pubKeyLen > index) revert OP_CheckMultisigFailed();
        bytes[] memory pubKeys = new bytes[](pubKeyLen);
        for (uint256 i; i < pubKeyLen; ++i) {
            pubKeys[i] = stack[index];
            --index;
            stack.pop();
        }

        // number of signatures
        temp = _getNumber();
        // at least 1 signature
        if (temp < 1) revert OP_CheckMultisigFailed();
        uint256 sigLen = uint256(temp);
        --index;
        // number of signatures plus op_0
        if (sigLen > index) revert OP_CheckMultisigFailed();
        bytes memory signature;
        uint256 j;
        uint256 verifiedSignatures;
        for (uint256 i; i < sigLen; ++i) {
            // ignore the last 1 byte
            signature = stack[index].readFromMemory(0, stack[index].length - 1);
            while (j < pubKeyLen) {
                if (_signatureHash.verify(signature, pubKeys[j])) {
                    ++verifiedSignatures;
                    ++j;
                    break;
                }
                ++j;
            }

            // failed to verify all signatures
            if (j == pubKeyLen && verifiedSignatures < sigLen) {
                stack[index] = "";
                return ++_ptr;
            }
            --index;
            stack.pop();
        }
        // check for op_0
        if (stack[index].length != 0) revert OP_CheckMultisigFailed();

        stack[index] = hex"01";
        return ++_ptr;
    }

    /**
     * Gets the number from the top of the stack
     * @dev The number is limited to signed 32-bit integers and is in little-endian
     * @return The result
     */
    function _getNumber() private returns (int32) {
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

        int256 res = isNegative ? -int256(num.bytesToUint256()) : int256(num.bytesToUint256());
        if (res > type(int32).max || res < type(int32).min) revert BadNumber();
        return int32(res);
    }

    /**
     * Pushes the number to the stack
     * @dev The number is limited to signed 32-bit integers and is in little-endian
     * @param _num - The number
     */
    function _pushNumber(int32 _num) private {
        if (_num == 0) {
            stack.push("");
            return;
        }

        int256 num = _num;
        bytes memory res;
        if (num < 0) {
            res = uint256(-num).uint256ToBytes().convertEndian();
            // if the highest bit is already set to 1,
            // add a byte with the highest bit set to 1
            if (res[res.length - 1] & 0x80 == 0x80) {
                res = bytes.concat(res, hex"80");
            } else {
                res[res.length - 1] = res[res.length - 1] | 0x80;
            }
        } else {
            res = uint256(int256(num)).uint256ToBytes().convertEndian();
            // if the highest bit is already set to 1,
            // add a byte with the highest bit set to 0
            if (res[res.length - 1] & 0x80 == 0x80) {
                res = bytes.concat(res, hex"00");
            }
        }

        stack.push(res);
    }
}
