// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {Signature} from "../src/lib/Structs.sol";
import {Script} from "../src/Script.sol";
import {Varint} from "../src/lib/Varint.sol";
import {Utils} from "../src/lib/Utils.sol";
import {SigLib} from "../src/lib/SigLib.sol";
import {SerialLib} from "../src/lib/SerialLib.sol";

contract MockScript is Script {
    function getStackElement(uint256 index) external view returns (bytes memory) {
        return stack[index];
    }

    function getStackLength() external view returns (uint256) {
        return stack.length;
    }
}

contract TestScript is BaseTest {
    using Varint for uint256;
    using Utils for uint256;
    using Utils for bytes;
    using SigLib for uint256;
    using SerialLib for Signature;
    using SerialLib for Point;

    MockScript mockScript;

    function setUp() public {
        mockScript = new MockScript();
    }

    function test_op_pushdata1() public {
        // less than 32 bytes
        bytes memory script = hex"4c0519bd1dfa19";
        _execute(script);
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"19bd1dfa19");

        // 32 bytes
        script = hex"4c20bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4";
        _execute(script);
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(1), hex"bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4");

        // more than 32 bytes
        script =
            hex"4c433fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5";
        _execute(script);
        assertEq(mockScript.getStackLength(), 3);
        assertEq(
            mockScript.getStackElement(2),
            hex"3fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5"
        );
    }

    function test_fuzz_op_pushdata1(bytes calldata _input) public {
        vm.assume(_input.length > 0 && _input.length < 255);
        bytes memory script = bytes.concat(hex"4c", _input.length.uint256ToBytes().convertEndian(), _input);

        _execute(script);
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), _input);
    }

    function test_op_pushdata2() public {
        // less than 32 bytes
        bytes memory script = hex"4d0500bd1dfa19fa";
        _execute(script);
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"bd1dfa19fa");

        // 32 bytes
        script = hex"4d2000bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4";
        _execute(script);
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(1), hex"bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4");

        // more than 32 bytes
        script =
            hex"4d43003fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5";
        _execute(script);
        assertEq(mockScript.getStackLength(), 3);
        assertEq(
            mockScript.getStackElement(2),
            hex"3fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5"
        );

        // way more than 32 bytes
        script =
            hex"4d0301931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129";
        _execute(script);
        assertEq(mockScript.getStackLength(), 4);
        assertEq(
            mockScript.getStackElement(3),
            hex"931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129"
        );

        // should revert if length is too long
        script = hex"4d1c02ffff";
        vm.expectRevert(Script.InvalidScript.selector);
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
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), _input);
    }

    function test_op_pushdata4() public {
        // less than 32 bytes
        bytes memory script = hex"4e05000000bd1dfa19fa";
        _execute(script);
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"bd1dfa19fa");

        // 32 bytes
        script = hex"4e20000000bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4";
        _execute(script);
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(1), hex"bc05b754df193a2591f5f9c02c5ef6c06fbb76926dee714512fa99aebdcea1b4");

        // more than 32 bytes
        script =
            hex"4e430000003fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5";
        _execute(script);
        assertEq(mockScript.getStackLength(), 3);
        assertEq(
            mockScript.getStackElement(2),
            hex"3fac6f0e66cc90d7d739ad6d55a3e25f3685c1d8ef713745d860bd4bb923ea13f31718e7d1d4b039ceb3fae3db81187709f3d9121ace054cf16dcea0fc34246f34abe5"
        );

        // way more than 32 bytes
        script =
            hex"4e03010000931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129";
        _execute(script);
        assertEq(mockScript.getStackLength(), 4);
        assertEq(
            mockScript.getStackElement(3),
            hex"931045e05493373ed81661e9dd81fc2f83c268dddb05e70461ea536cd3560437263e8b65faac314cb3cc538ae7519791f269e8acd38347a74266e7c1cfba2b6db9a45eb540d36f28f3e3d96a3a221c23bb0423dedf040afc55dcbeb62db2e460aaaa780bcfd2afbb447222356a9470286ecd60338e375f7b835b7e1746db5013b27659660fa99255f0958d79b59a19f7dfa18f3999502bbd117fa297468f26d8b9f041cc3426ecfce8d765e8ea71f04ca99955a29b1b4217fc3715c412a89b96387c35c08decc6bba2dc38424acf468211c56fa8374a7411becbe19874407cd5613ac9a0506d0e3a0594b1c6d855ce66bb311b8dbbd7df01c66ef3a6f6038ac240b129"
        );

        // should revert if length is too long
        script = hex"4e1c02ffff";
        vm.expectRevert(Script.InvalidScript.selector);
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
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), _input);
    }

    function test_op_1() public {
        _execute(hex"51");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");
    }

    function test_op_0() public {
        // push 1 so script is valid
        _execute(hex"0051");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");
    }

    function test_op_2() public {
        _execute(hex"52");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"02");
    }

    function test_op_verify() public {
        // push 1 to verify, then push 1 again so script is valid
        _execute(hex"516951");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"6951");

        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"6951");

        vm.expectRevert(Script.InvalidScript.selector);
        _execute(hex"006951");

        vm.expectRevert(Script.InvalidScript.selector);
        _execute(hex"4c0519bd1dfa196951");
    }

    function test_op_drop() public {
        _execute(hex"517551");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        _execute(hex"51517551");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"01");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        _execute(hex"514c0519bd1dfa19517551");
        assertEq(mockScript.getStackLength(), 3);
        assertEq(mockScript.getStackElement(0), hex"01");
        assertEq(mockScript.getStackElement(1), hex"19bd1dfa19");
        assertEq(mockScript.getStackElement(2), hex"01");

        mockScript = new MockScript();
        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"7551");
    }

    function test_op_dup() public {
        _execute(hex"5176");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"01");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        _execute(hex"515176");
        assertEq(mockScript.getStackLength(), 3);
        assertEq(mockScript.getStackElement(0), hex"01");
        assertEq(mockScript.getStackElement(1), hex"01");
        assertEq(mockScript.getStackElement(2), hex"01");

        mockScript = new MockScript();
        _execute(hex"514c0519bd1dfa1976");
        assertEq(mockScript.getStackLength(), 3);
        assertEq(mockScript.getStackElement(0), hex"01");
        assertEq(mockScript.getStackElement(1), hex"19bd1dfa19");
        assertEq(mockScript.getStackElement(2), hex"19bd1dfa19");

        mockScript = new MockScript();
        _execute(hex"007651");
        assertEq(mockScript.getStackLength(), 3);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"");
        assertEq(mockScript.getStackElement(2), hex"01");

        mockScript = new MockScript();
        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"7651");
    }

    function test_op_swap() public {
        _execute(hex"51527c");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"02");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        _execute(hex"5251007c");
        assertEq(mockScript.getStackLength(), 3);
        assertEq(mockScript.getStackElement(0), hex"02");
        assertEq(mockScript.getStackElement(1), hex"");
        assertEq(mockScript.getStackElement(2), hex"01");

        mockScript = new MockScript();
        _execute(hex"4c0519bd1dfa19527c");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"02");
        assertEq(mockScript.getStackElement(1), hex"19bd1dfa19");

        mockScript = new MockScript();
        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"7c");

        vm.expectRevert(Script.StackIsEmpty.selector);
        _execute(hex"517c");
    }

    function test_op_equal() public {
        _execute(hex"515187");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        _execute(hex"4c0519bd1dfa194c0519bd1dfa1987");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        vm.expectRevert(Script.InvalidScript.selector);
        _execute(hex"515287");
    }

    function test_op_equalverify() public {
        _execute(hex"51518851");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        _execute(hex"4c0519bd1dfa194c0519bd1dfa198851");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        vm.expectRevert(Script.InvalidScript.selector);
        _execute(hex"515288");
    }

    function test_op_not() public {
        _execute(hex"519151");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        _execute(hex"0091");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        _execute(hex"529151");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");
    }

    function test_op_add() public {
        _execute(hex"00009351");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        _execute(hex"510093");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        _execute(hex"5152935293");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"05");

        mockScript = new MockScript();
        _execute(hex"4c01815293");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        _execute(hex"4c0181519351");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        vm.expectRevert(Script.InvalidScript.selector);
        _execute(hex"4c0502000080005193");

        vm.expectRevert(Script.InvalidScript.selector);
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
            assertEq(mockScript.getStackLength(), 2);
            assertEq(mockScript.getStackElement(0), expected);
            assertEq(mockScript.getStackElement(1), hex"01");
        } else {
            _execute(script);
            assertEq(mockScript.getStackLength(), 1);
            assertEq(mockScript.getStackElement(0), expected);
        }
    }

    function test_op_sub() public {
        _execute(hex"00009451");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        _execute(hex"510094");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"81");

        mockScript = new MockScript();
        _execute(hex"5152945294");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        _execute(hex"5152935194");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"82");

        mockScript = new MockScript();
        _execute(hex"4c01815294");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"03");

        mockScript = new MockScript();
        _execute(hex"4c01814c01819451");
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");

        mockScript = new MockScript();
        vm.expectRevert(Script.InvalidScript.selector);
        _execute(hex"4c0502000080005194");

        vm.expectRevert(Script.InvalidScript.selector);
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
            assertEq(mockScript.getStackLength(), 2);
            assertEq(mockScript.getStackElement(0), expected);
            assertEq(mockScript.getStackElement(1), hex"01");
        } else {
            _execute(script);
            assertEq(mockScript.getStackLength(), 1);
            assertEq(mockScript.getStackElement(0), expected);
        }
    }

    function test_op_hash160() public {
        _execute(hex"00a9");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");

        mockScript = new MockScript();
        _execute(hex"51a9");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"c51b66bced5e4491001bd702669770dccf440982");

        mockScript = new MockScript();
        _execute(hex"20568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1ea9");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"3eb9ff8d8e52777f39e287bba905c79162059438");

        mockScript = new MockScript();
        _execute(
            hex"41568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1e6a0a817c8921da25c9c07832ff32c835a461b632c12f2fef760938ebdd80e357afa9"
        );
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"c81b5d6406070f69e9a2af5f80f43c1d6e78774b");
    }

    function test_op_hash256() public {
        _execute(hex"00aa");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

        mockScript = new MockScript();
        _execute(hex"51aa");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"9c12cfdc04c74584d787ac3d23772132c18524bc7ab28dec4219b8fc5b425f70");

        mockScript = new MockScript();
        _execute(hex"20568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1eaa");
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"5ecbec968078ccf9e48105e3dd825b2152abb9889202320d91e4b95312cf85ee");

        mockScript = new MockScript();
        _execute(
            hex"41568acdb6e91a0b2b5bcec818fce9a9ff478ce821ee7ee80f403002a4d0264f1e6a0a817c8921da25c9c07832ff32c835a461b632c12f2fef760938ebdd80e357afaa"
        );
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"4b1173e38a153ea1c35ea36bb40c084f5b372415ccb0c5d57968edca2e12a306");
    }

    function test_op_checksig() public {
        // TODO
        uint256 msgHash = 42;
        bytes memory signature = msgHash.sign(privateKey).serializeSignature();
        bytes memory publicKey = pubKey.serializePublicKey(true);
        bytes memory script = bytes.concat(
            hex"4c",
            bytes1(uint8(signature.length)),
            signature,
            hex"4c",
            bytes1(uint8(publicKey.length)),
            publicKey,
            hex"ac"
        );
        _execute(script);
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        signature = msgHash.sign(anotherPrivateKey).serializeSignature();
        publicKey = anotherPubKey.serializePublicKey(false);
        script = bytes.concat(
            hex"4c",
            bytes1(uint8(signature.length)),
            signature,
            hex"4c",
            bytes1(uint8(publicKey.length)),
            publicKey,
            hex"ac"
        );
        _execute(script);
        assertEq(mockScript.getStackLength(), 1);
        assertEq(mockScript.getStackElement(0), hex"01");

        mockScript = new MockScript();
        signature = msgHash.sign(privateKey).serializeSignature();
        publicKey = anotherPubKey.serializePublicKey(false);
        script = bytes.concat(
            hex"4c",
            bytes1(uint8(signature.length)),
            signature,
            hex"4c",
            bytes1(uint8(publicKey.length)),
            publicKey,
            hex"ac",
            hex"51"
        );
        _execute(script);
        assertEq(mockScript.getStackLength(), 2);
        assertEq(mockScript.getStackElement(0), hex"");
        assertEq(mockScript.getStackElement(1), hex"01");
    }

    function _execute(bytes memory _script) internal {
        mockScript.execute(bytes.concat(_script.length.toVarint(), _script));
    }

    function _intToBytes(int32 _x) internal pure returns (bytes memory res) {
        if (_x == 0) return hex"";

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
