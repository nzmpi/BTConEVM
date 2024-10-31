// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {Script} from "../src/Script.sol";
import {SerialLib} from "../src/lib/SerialLib.sol";
import {SigLib} from "../src/lib/SigLib.sol";
import {Signature} from "../src/lib/Structs.sol";
import {Utils} from "../src/lib/Utils.sol";
import {Varint} from "../src/lib/Varint.sol";

contract MockScript is Script {
    function getStackElement(uint256 index) external view returns (bytes memory res) {
        uint256 stackSlot = 1;
        uint256 lenSlot = uint256(keccak256(abi.encode(stackSlot))) + index;
        bytes32 elementSlot = keccak256(abi.encode(lenSlot));
        assembly {
            // get free memory pointer
            res := mload(0x40)
            let len := sload(lenSlot)

            switch iszero(and(len, 1))
            // more than 32 bytes
            case 0 {
                // value is length * 2 + 1
                len := div(sub(len, 1), 2)
                mstore(res, len)
                len := add(div(len, 0x20), gt(mod(len, 0x20), 0))
                let offset := res
                for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                    offset := add(offset, 0x20)
                    mstore(offset, sload(add(elementSlot, i)))
                }
                // update free memory pointer
                mstore(0x40, add(offset, 0x20))
            }
            // less than 32 bytes
            case 1 {
                // value is length * 2
                mstore(res, div(and(len, 0xff), 2))
                mstore(add(res, 0x20), len)
                // update free memory pointer
                mstore(0x40, add(res, add(res, 0x40)))
            }
            default { revert(0, 0) }
        }
    }
}

contract TestScript is BaseTest {
    using SerialLib for *;
    using SigLib for uint256;
    using Utils for *;
    using Varint for uint256;

    uint256 signatureHash;
    MockScript mock;

    function setUp() public {
        mock = new MockScript();
        delete signatureHash;
    }

    function test_op_0() public {
        // push 1 so script is valid
        _execute(hex"0051");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), hex"01");
    }

    function test_op_pushdata1() public {
        // less than 32 bytes
        bytes memory script = hex"4c0519bd1dfa19";
        _execute(script);
        assertEq(mock.getStackElement(0), hex"19bd1dfa19");

        // 32 bytes
        script = hex"4c20bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4";
        _execute(script);
        assertEq(mock.getStackElement(0), hex"bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4");

        // more than 32 bytes
        script =
            hex"4c433fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5";
        _execute(script);
        assertEq(
            mock.getStackElement(0),
            hex"3fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5"
        );
    }

    function test_fuzz_op_pushdata1(bytes calldata _input) public {
        vm.assume(_input.length > 0 && _input.length < 255);
        bytes memory script = bytes.concat(hex"4c", _input.length.uint256ToBytes().convertEndian(), _input);

        _execute(script);
        assertEq(mock.getStackElement(0), _input);
    }

    function test_op_pushdata2() public {
        // less than 32 bytes
        bytes memory script = hex"4d0500bd1dfa19fa";
        _execute(script);
        assertEq(mock.getStackElement(0), hex"bd1dfa19fa");

        // 32 bytes
        script = hex"4d2000bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4";
        _execute(script);
        assertEq(mock.getStackElement(0), hex"bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4");

        // more than 32 bytes
        script =
            hex"4d43003fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5";
        _execute(script);
        assertEq(
            mock.getStackElement(0),
            hex"3fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5"
        );

        // way more than 32 bytes
        script =
            hex"4d0301931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129";
        _execute(script);
        assertEq(
            mock.getStackElement(0),
            hex"931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129"
        );

        // should revert if the length is too long
        script = hex"4d1c02ffff";
        vm.expectRevert(abi.encodeWithSelector(Script.MaxLengthPushdata.selector, 0x021c));
        _execute(script);
    }

    function test_fuzz_op_pushdata2(bytes calldata _input) public {
        vm.assume(_input.length > 0 && _input.length < 520);
        bytes memory script;
        if (_input.length < 256) {
            script =
                bytes.concat(hex"4d", bytes.concat(hex"00", _input.length.uint256ToBytes()).convertEndian(), _input);
        } else {
            script = bytes.concat(hex"4d", _input.length.uint256ToBytes().convertEndian(), _input);
        }

        _execute(script);
        assertEq(mock.getStackElement(0), _input);
    }

    function test_op_pushdata4() public {
        // less than 32 bytes
        bytes memory script = hex"4e05000000bd1dfa19fa";
        _execute(script);
        assertEq(mock.getStackElement(0), hex"bd1dfa19fa");

        // 32 bytes
        script = hex"4e20000000bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4";
        _execute(script);
        assertEq(mock.getStackElement(0), hex"bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4");

        // more than 32 bytes
        script =
            hex"4e430000003fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5";
        _execute(script);
        assertEq(
            mock.getStackElement(0),
            hex"3fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5"
        );

        // way more than 32 bytes
        script =
            hex"4e03010000931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129";
        _execute(script);
        assertEq(
            mock.getStackElement(0),
            hex"931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129"
        );

        // should revert if the length is too long
        script = hex"4e1c02ffff";
        vm.expectRevert(abi.encodeWithSelector(Script.MaxLengthPushdata.selector, 0xffff021c));
        _execute(script);
    }

    function test_fuzz_op_pushdata4(bytes calldata _input) public {
        vm.assume(_input.length > 0 && _input.length < 520);
        bytes memory script;
        if (_input.length < 256) {
            script =
                bytes.concat(hex"4e", bytes.concat(hex"000000", _input.length.uint256ToBytes()).convertEndian(), _input);
        } else {
            script =
                bytes.concat(hex"4e", bytes.concat(hex"0000", _input.length.uint256ToBytes()).convertEndian(), _input);
        }

        _execute(script);
        assertEq(mock.getStackElement(0), _input);
    }

    function test_fuzz_op_n(uint256 n) public {
        n = bound(n, 0x51, 0x60);
        _execute(n.uint256ToBytes());
        assertEq(mock.getStackElement(0), (n - 0x50).uint256ToBytes());
    }

    function test_op_verify() public {
        // push 1 to verify, then push 1 again so script is valid
        _execute(hex"516951");
        assertEq(mock.getStackElement(0), hex"01");

        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"6951");

        vm.expectRevert(Script.OP_VerifyFailed.selector);
        _execute(hex"006951");

        vm.expectRevert(Script.OP_VerifyFailed.selector);
        _execute(hex"4c0519bd1dfa196951");
    }

    function test_op_drop() public {
        _execute(hex"517551");
        assertEq(mock.getStackElement(0), hex"01");

        _execute(hex"51517551");
        assertEq(mock.getStackElement(0), hex"01");
        assertEq(mock.getStackElement(1), hex"01");

        _execute(hex"514c0519bd1dfa19517551");
        assertEq(mock.getStackElement(0), hex"01");
        assertEq(mock.getStackElement(1), hex"19bd1dfa19");
        assertEq(mock.getStackElement(2), hex"01");

        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"7551");
    }

    function test_op_dup() public {
        _execute(hex"5176");
        assertEq(mock.getStackElement(0), hex"01");
        assertEq(mock.getStackElement(1), hex"01");

        _execute(hex"515176");
        assertEq(mock.getStackElement(0), hex"01");
        assertEq(mock.getStackElement(1), hex"01");
        assertEq(mock.getStackElement(2), hex"01");

        _execute(hex"514c0519bd1dfa1976");
        assertEq(mock.getStackElement(0), hex"01");
        assertEq(mock.getStackElement(1), hex"19bd1dfa19");
        assertEq(mock.getStackElement(2), hex"19bd1dfa19");

        _execute(hex"007651");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), "");
        assertEq(mock.getStackElement(2), hex"01");

        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"7651");
    }

    function test_op_swap() public {
        _execute(hex"51527c");
        assertEq(mock.getStackElement(0), hex"02");
        assertEq(mock.getStackElement(1), hex"01");

        _execute(hex"5251007c");
        assertEq(mock.getStackElement(0), hex"02");
        assertEq(mock.getStackElement(1), "");
        assertEq(mock.getStackElement(2), hex"01");

        _execute(hex"4c0519bd1dfa19527c");
        assertEq(mock.getStackElement(0), hex"02");
        assertEq(mock.getStackElement(1), hex"19bd1dfa19");

        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"7c");

        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"517c");
    }

    function test_op_equal() public {
        _execute(hex"515187");
        assertEq(mock.getStackElement(0), hex"01");

        _execute(hex"4c0519bd1dfa194c0519bd1dfa1987");
        assertEq(mock.getStackElement(0), hex"01");

        vm.expectRevert(Script.ScriptFailed.selector);
        _execute(hex"515287");
    }

    function test_op_equalverify() public {
        _execute(hex"51518851");
        assertEq(mock.getStackElement(0), hex"01");

        _execute(hex"4c0519bd1dfa194c0519bd1dfa198851");
        assertEq(mock.getStackElement(0), hex"01");

        vm.expectRevert(Script.OP_EqualVerifyFailed.selector);
        _execute(hex"515288");
    }

    function test_op_not() public {
        _execute(hex"519151");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), hex"01");

        _execute(hex"0091");
        assertEq(mock.getStackElement(0), hex"01");

        _execute(hex"529151");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), hex"01");
    }

    function test_op_add() public {
        _execute(hex"00009351");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), hex"01");

        _execute(hex"510093");
        assertEq(mock.getStackElement(0), hex"01");

        _execute(hex"5152935293");
        assertEq(mock.getStackElement(0), hex"05");

        _execute(hex"4c01815293");
        assertEq(mock.getStackElement(0), hex"01");

        _execute(hex"4c0181519351");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), hex"01");

        vm.expectRevert(Script.BadNumber.selector);
        _execute(hex"4c0502000080005193");

        vm.expectRevert(Script.BadNumber.selector);
        _execute(hex"4c0502000080805193");
    }

    function test_fuzz_op_add(int32 x, int32 y) public {
        int32 z;
        unchecked {
            z = x + y;
        }
        bytes memory expected = _intToBytes(z);
        bytes memory xBytes = _intToBytes(x);
        bytes memory yBytes = _intToBytes(y);
        bytes memory script = bytes.concat(
            hex"4c", bytes1(uint8(xBytes.length)), xBytes, hex"4c", bytes1(uint8(yBytes.length)), yBytes, hex"93"
        );
        if (z == 0) {
            script = bytes.concat(script, hex"51");
            _execute(script);
            assertEq(mock.getStackElement(0), expected);
            assertEq(mock.getStackElement(1), hex"01");
        } else {
            _execute(script);
            assertEq(mock.getStackElement(0), expected);
        }
    }

    function test_op_sub() public {
        _execute(hex"00009451");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), hex"01");

        _execute(hex"510094");
        assertEq(mock.getStackElement(0), hex"81");

        _execute(hex"5152945294");
        assertEq(mock.getStackElement(0), hex"01");

        _execute(hex"5152935194");
        assertEq(mock.getStackElement(0), hex"82");

        _execute(hex"4c01815294");
        assertEq(mock.getStackElement(0), hex"03");

        _execute(hex"4c01814c01819451");
        assertEq(mock.getStackElement(0), "");
        assertEq(mock.getStackElement(1), hex"01");

        vm.expectRevert(Script.BadNumber.selector);
        _execute(hex"4c0502000080005194");

        vm.expectRevert(Script.BadNumber.selector);
        _execute(hex"4c0502000080805194");
    }

    function test_fuzz_op_sub(int32 x, int32 y) public {
        int32 z;
        unchecked {
            z = y - x;
        }
        bytes memory expected = _intToBytes(z);
        bytes memory xBytes = _intToBytes(x);
        bytes memory yBytes = _intToBytes(y);
        bytes memory script = bytes.concat(
            hex"4c", bytes1(uint8(xBytes.length)), xBytes, hex"4c", bytes1(uint8(yBytes.length)), yBytes, hex"94"
        );
        if (z == 0) {
            script = bytes.concat(script, hex"51");
            _execute(script);
            assertEq(mock.getStackElement(0), expected);
            assertEq(mock.getStackElement(1), hex"01");
        } else {
            _execute(script);
            assertEq(mock.getStackElement(0), expected);
        }
    }

    function test_op_hash160() public {
        _execute(hex"00a9");
        assertEq(mock.getStackElement(0), hex"b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");

        _execute(hex"51a9");
        assertEq(mock.getStackElement(0), hex"c51b66bced5e4491001bd702669770dccf440982");

        _execute(hex"20568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1ea9");
        assertEq(mock.getStackElement(0), hex"3eb9ff8d8e52777f39e287bba905c79162059438");

        _execute(
            hex"41568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1e6a0a817c8921da25c9c07832ff32c835a461b632c12f2fef760938ebdd80e357afa9"
        );
        assertEq(mock.getStackElement(0), hex"c81b5d6406070f69e9a2af5f80f43c1d6e78774b");
    }

    function test_op_hash256() public {
        _execute(hex"00aa");
        assertEq(mock.getStackElement(0), hex"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

        _execute(hex"51aa");
        assertEq(mock.getStackElement(0), hex"9c12cfdc04c74584d787ac3d23772132c18524bc7ab28dec4219b8fc5b425f70");

        _execute(hex"20568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1eaa");
        assertEq(mock.getStackElement(0), hex"5ecbec968078ccf9e48105e3dd825b2152abb9889202320d91e4b95312cf85ee");

        _execute(
            hex"41568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1e6a0a817c8921da25c9c07832ff32c835a461b632c12f2fef760938ebdd80e357afaa"
        );
        assertEq(mock.getStackElement(0), hex"4b1173e38a153ea1c35ea36bb40c084f5b372415ccb0c5d57968edca2e12a306");
    }

    function test_op_checksig() public {
        signatureHash = uint256(keccak256("random"));
        bytes memory signature = signatureHash.sign(privateKey).serializeSignature();
        bytes memory publicKey = pubKey.serializePublicKey(true);
        bytes memory script = bytes.concat(
            signature.length.getLengthForScript(), signature, publicKey.length.getLengthForScript(), publicKey, hex"ac"
        );
        _execute(script);
        assertEq(mock.getStackElement(0), hex"01");

        signature = signatureHash.sign(anotherPrivateKey).serializeSignature();
        publicKey = anotherPubKey.serializePublicKey(false);
        script = bytes.concat(
            signature.length.getLengthForScript(), signature, publicKey.length.getLengthForScript(), publicKey, hex"ac"
        );
        _execute(script);
        assertEq(mock.getStackElement(0), hex"01");

        signature = signatureHash.sign(privateKey).serializeSignature();
        publicKey = anotherPubKey.serializePublicKey(false);
        script = bytes.concat(
            signature.length.getLengthForScript(), signature, publicKey.length.getLengthForScript(), publicKey, hex"ac"
        );
        vm.expectRevert(Script.ScriptFailed.selector);
        _execute(script);
    }

    function test_op_checkmultisig() public {
        signatureHash = uint256(keccak256("random hash"));
        bytes memory signature1 = signatureHash.sign(privateKey).serializeSignature();
        bytes memory signature2 = signatureHash.sign(anotherPrivateKey).serializeSignature();
        bytes memory signature3 = signatureHash.sign(thirdPrivateKey).serializeSignature();
        bytes memory publicKey1 = pubKey.serializePublicKey(true);
        bytes memory publicKey2 = anotherPubKey.serializePublicKey(true);
        bytes memory publicKey3 = thirdPubKey.serializePublicKey(true);

        // 1-of-2 multisig
        bytes memory script = bytes.concat(
            hex"00",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            hex"51",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        _execute(script);
        assertEq(mock.getStackElement(0), hex"01");

        // 2-of-2 multisig
        script = bytes.concat(
            hex"00",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            (signature2.length + 1).getLengthForScript(),
            signature2,
            hex"01", // SIGHASH_ALL
            hex"52",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        _execute(script);
        assertEq(mock.getStackElement(0), hex"01");

        // 1-of-3 multisig
        script = bytes.concat(
            hex"00",
            (signature2.length + 1).getLengthForScript(),
            signature2,
            hex"01", // SIGHASH_ALL
            hex"51",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            publicKey3.length.getLengthForScript(),
            publicKey3,
            hex"53",
            hex"ae"
        );
        _execute(script);
        assertEq(mock.getStackElement(0), hex"01");

        // 2-of-3 multisig
        script = bytes.concat(
            hex"00",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            (signature3.length + 1).getLengthForScript(),
            signature3,
            hex"01", // SIGHASH_ALL
            hex"52",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            publicKey3.length.getLengthForScript(),
            publicKey3,
            hex"53",
            hex"ae"
        );
        _execute(script);
        assertEq(mock.getStackElement(0), hex"01");

        // invalid 1-of-2 multisig, wrong signature
        script = bytes.concat(
            hex"00",
            (signature3.length + 1).getLengthForScript(),
            signature3,
            hex"01", // SIGHASH_ALL
            hex"51",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        vm.expectRevert(Script.ScriptFailed.selector);
        _execute(script);

        // invalid 2-of-2 multisig, 1 wrong signature
        script = bytes.concat(
            hex"00",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            (signature3.length + 1).getLengthForScript(),
            signature3,
            hex"01", // SIGHASH_ALL
            hex"52",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        vm.expectRevert(Script.ScriptFailed.selector);
        _execute(script);

        // invalid 2-of-2 multisig, reusing signature
        script = bytes.concat(
            hex"00",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            hex"52",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        vm.expectRevert(Script.ScriptFailed.selector);
        _execute(script);

        // invalid 2-of-2 multisig, wrong order
        script = bytes.concat(
            hex"00",
            (signature2.length + 1).getLengthForScript(),
            signature2,
            hex"01", // SIGHASH_ALL
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            hex"52",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        vm.expectRevert(Script.ScriptFailed.selector);
        _execute(script);

        // no public keys
        script = bytes.concat(
            hex"00",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            hex"51",
            hex"00",
            hex"ae"
        );
        vm.expectRevert(Script.OP_CheckMultisigFailed.selector);
        _execute(script);

        // not enough public keys
        script = bytes.concat(hex"00", publicKey1.length.getLengthForScript(), publicKey1, hex"52", hex"ae");
        vm.expectRevert(Script.OP_CheckMultisigFailed.selector);
        _execute(script);

        // no signatures
        script = bytes.concat(
            hex"00",
            hex"00",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        vm.expectRevert(Script.OP_CheckMultisigFailed.selector);
        _execute(script);

        // not enough signatures
        script = bytes.concat(
            hex"00",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            hex"52",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        vm.expectRevert(Script.OP_CheckMultisigFailed.selector);
        _execute(script);

        // no op_0
        script = bytes.concat(
            hex"51",
            (signature1.length + 1).getLengthForScript(),
            signature1,
            hex"01", // SIGHASH_ALL
            hex"51",
            publicKey1.length.getLengthForScript(),
            publicKey1,
            publicKey2.length.getLengthForScript(),
            publicKey2,
            hex"52",
            hex"ae"
        );
        vm.expectRevert(Script.OP_CheckMultisigFailed.selector);
        _execute(script);
    }

    function _execute(bytes memory _script) internal {
        mock.execute(bytes.concat(_script.length.toVarint(), _script), bytes32(signatureHash), new bytes[](0));
    }

    function _intToBytes(int32 _x) internal pure returns (bytes memory res) {
        if (_x == 0) return "";

        int256 x = _x;
        if (x < 0) {
            res = uint256(-x).uint256ToBytes().convertEndian();
            if (res[res.length - 1] & 0x80 == 0x80) {
                res = bytes.concat(res, hex"80");
            } else {
                res[res.length - 1] = res[res.length - 1] | 0x80;
            }
        } else {
            res = uint256(x).uint256ToBytes().convertEndian();
            if (res[res.length - 1] & 0x80 == 0x80) {
                res = bytes.concat(res, hex"00");
            }
        }
    }
}
