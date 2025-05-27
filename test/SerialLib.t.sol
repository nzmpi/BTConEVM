// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SerialLib} from "../src/lib/SerialLib.sol";
import {SigLib} from "../src/lib/SigLib.sol";
import "../src/lib/Structs.sol";
import "./utils/BaseTest.sol";

contract MockSerialLib {
    using SerialLib for bytes;

    function parsePublicKey(bytes memory _data) external pure returns (Point memory) {
        return _data.parsePublicKey();
    }
}

contract TestSerialLib is BaseTest {
    using SerialLib for *;
    using SigLib for uint256;
    using ECBTC for uint256;

    bytes[5] rawTxs = [
        bytes(
            hex"010000000130303ea774da061109b6f5b0cafc909e6abacf6a52501c71ab9f627b174cea5901000000d90047304402203285484f30722560cfd2c8f346c58be14791ac2859b9ef5aebd31373b9d9ed3802202a40bf31a4a297ba3130920707a2d5315019f33cd175270c198e81727460c96401473044022001888d61eb5d3d5528098531a7dbdb5233748712f069f022a2135e6175bb66a9022064860cb4fb71c3879dce3835765b7f76dbf35621f55729b8c69623e55d13811f01475221022b6dc4281a12a37a00ab920fd9ab1d4b509e288122cf406cd3d0bfb2f5471706210392e4ecdd0af74a2d05b9448343b22fac173c1618c62caf2039efb09c7e67f2d452aeffffffff02b08549030000000017a914b4eef9a952db30866728f788bb469bae8d5fc52687d5df87370000000017a91483e02ab859c6ab1e4ee45b20492eaca173f0b6fb8700000000"
        ),
        hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0f04bedf061a02d405062f503253482fffffffff0100f2052a0100000043410450d5ef5bb3d8a893a4b1fcf2e9d8f898d782fbf22a887f3fbafd22b06d225a5754be9b2cd0d00ee2c3715bfced2e403a6e0d1bf2716ebfd6e6f9ddac1924b6e7ac00000000",
        hex"01000000035f6b1748d9a33b20dd763b9bea17d21f7ea3825a3a11269e4af2aebde8773367000000006c493046022100ed23c8cbb485acd3c073137803584b2a2c91f350d17b54bd1a10a4b814dfad44022100a567ba44f3a3b0769ae96b9af42f4a33827eaa92f5c40deb5886e0009a70f39d012102e2d7f7486ced79f3a4fcc26e4848bd2de484397ba8df365d468acbeecd3562b8ffffffffd7bbaf80903175e219445663b3d23438e8bbcd876785eede9383b81061576966000000006b483045022100e7ad48a20853c7cc1f419589407173b5e82c37e5715f7bc08ed6682381b0adcc0220200ec21da4a684f870bc8065f8a92e669421ca4c747278cc7a0aa5ad44b6555401210342dd1c67748c439ba4567a325c842caa3a16ba5200e730c47af2e5aa581903edffffffffa9fbff9f4dccc331d2bbca29fe1bf6b97f724e344a20c7f7b872732715ca0e3c000000006b483045022100b473b18f9942a9097e5e8677fd4c0442458c193770a65de258928c9f1d9478e902201f41799ef679577fdf0b2783962d1f64da1f828d994991afdff5465bfd8970e9012102f14306fcfc9a8138cc86469c5d2b40f28d885a19faf45b2be6578ea10e910252ffffffff020084d717000000001976a914f5bc94a48ad7f290c58b4fb970514cbf99daf30b88ac47420f00000000001976a914f094dc8e530cdc17221fc936399fcf0da5c3cb4a88ac00000000",
        hex"02000000000101efac8070a05a35ca1f24cb6b2928465ea241bd2ca6a5d674e5734d9ade5e9d150000000017160014a5b404e24cfc890850c410b0c4aa266d021b1125fdffffff02c0cd1700000000001976a914d8e2f29deeb25460da0543c4baf0a43591d3584a88acbfe534020000000017a914aa28aaf1b7949dc848d025434c0ef3cc152738f4870247304402205c96b8cf7f64a49bea1950f124dd078741d0eb4b9db37a4e0a87ffa9760e5e4b0220165d6a90848743246b42e4b4e46966d777f26fcb5404517177ab840d2518ab85012103ed4a30070a474a35eda68c1dd71fc7db3aa646a5e80b43d666d27d59adcb856a8e500900",
        hex"0100000000010299908210f33c8055dd4193a8801c4f60297c40b1f479c517f5fff92857d8c66f020000006a4730440220618d6a5b0e9758e6a18ee4eb2737fbce220745658d9bea3f145408b67e83f7af02205915852662634783220ed58370b984081e6b0abdbcd2caeec9a72f19f1a5ddd101210326efb2708b4e0e1950706a4d7cbaa063ed2aa32afbedc5793a533a723f767fbeffffffff1fb4851ea0efe0a1efa09bdd8cf21d85ff649f51d49e5eb60eab6e2a7f0c280b010000001716001470c79be6d74420b7920dca35849cb5a37e2e60beffffffff040000000000000000166a146f6d6e69000000000000001f000000912571427cf34e0a000000000017a91438a9ee60e46a957475e429585dc63bb6fd84dd288722020000000000001976a914e3d41f555febacef735148156e7f3ce866d0a00188ac22020000000000001976a9148b9237e241576595d294c07a793847fd2b628b8088ac000247304402205c2441e0feb05bba4890d28bd95449c2a3d26703af552f84d4a272815e25cd6b022068eb6f6acdd7652ea0fc2796d56aa2e7a4347497e05159d90acd0c775cff31b1012102a879a0629b5c6cbdba08f41601ad331e1e100961b19e6396e76a576acdb8ce3300000000"
    ];

    bytes[5] rawBlocks = [
        bytes(
            hex"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c00"
        ),
        hex"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e3629900",
        hex"00a07021586496e770916eb8f96ea80bc8234bec3ff1dd5f18d504000000000000000000ceee572ab32a562d81d62739aa898e45c1b199b1027bff5b2439ce4318003e1463f1586401dd05170309327c00",
        hex"0000c0205fe93fb0cd61c639c6d112258ba3d739c3dbaec6e76a0d0000000000000000000ba3c93411fca1c7da46a5d8a05a27272d71edc0ddbf37ce289afb9615a75107622cca5f56b10e171cc45f7900",
        hex"00e0ff3fcf989b1865a0b521e8c1cfbab22d644659692be568ae07000000000000000000d9f0bb3926ead82b9e9581a990f9ba6d49997e63e8ca17513eb88a4cf4e715bd49adfa5ef2d411170e4626c5028581456ab981e71b43e39d72d79cca362f9558b60c99029f226ef07d5d83c44a61d30b840881c84f8f6626756827a140119ac68a58fee2c445f1fad50bd2504e"
    ];

    function test_serializePublicKey() public view {
        bytes memory result = pubKey.serializePublicKey(false);
        bytes memory expected = bytes.concat(bytes1(0x04), bytes32(pubKey.x), bytes32(pubKey.y));

        assertEq(result, expected, "Uncompressed public key should be serialized correctly");

        result = pubKey.serializePublicKey(true);
        expected = bytes.concat(bytes1(0x03), bytes32(pubKey.x));
        assertEq(result, expected, "Compressed public key should be serialized correctly");
    }

    function test_fuzz_serializePublicKey(uint256 _privateKey, bool _isCompressed) public pure {
        Point memory pubKey_ = _privateKey.mulG();
        bytes memory result = pubKey_.serializePublicKey(_isCompressed);
        bytes memory expected;
        if (_isCompressed) {
            if (pubKey_.y % 2 == 0) {
                expected = bytes.concat(bytes1(0x02), bytes32(pubKey_.x));
            } else {
                expected = bytes.concat(bytes1(0x03), bytes32(pubKey_.x));
            }
            assertEq(result, expected, "Compressed public key should be serialized correctly");
        } else {
            expected = bytes.concat(bytes1(0x04), bytes32(pubKey_.x), bytes32(pubKey_.y));
            assertEq(result, expected, "Uncompressed public key should be serialized correctly");
        }
    }

    function test_parsePublicKey() public {
        bytes memory PKSerlial = pubKey.serializePublicKey(false);
        Point memory result = PKSerlial.parsePublicKey();
        assertEq(result.x, pubKey.x, "Wrong uncompressed public key x-coordinate");
        assertEq(result.y, pubKey.y, "Wrong uncompressed public key y-coordinate");

        PKSerlial = pubKey.serializePublicKey(true);
        result = PKSerlial.parsePublicKey();
        assertEq(result.x, pubKey.x, "Wrong compressed public key x-coordinate");
        assertEq(result.y, pubKey.y, "Wrong compressed public key y-coordinate");

        // multiple reverts don't work with internal function calls
        MockSerialLib mock = new MockSerialLib();

        PKSerlial = hex"04fff3423acb";
        vm.expectRevert(SerialLib.BadData.selector);
        mock.parsePublicKey(PKSerlial);

        PKSerlial = hex"02fff3423acb";
        vm.expectRevert(SerialLib.BadData.selector);
        mock.parsePublicKey(PKSerlial);

        PKSerlial = hex"fff3423acb";
        vm.expectRevert(SerialLib.BadData.selector);
        mock.parsePublicKey(PKSerlial);
    }

    function test_fuzz_parsePublicKey(uint256 _privateKey, bool _isCompressed) public pure {
        Point memory pubKey_ = _privateKey.mulG();
        Point memory result = pubKey_.serializePublicKey(_isCompressed).parsePublicKey();
        assertEq(result.x, pubKey_.x, "Wrong public key x-coordinate");
        assertEq(result.y, pubKey_.y, "Wrong public key y-coordinate");
    }

    function test_serializeSignature() public view {
        Signature memory sig = messageHash.sign(privateKey);
        bytes memory result = sig.serializeSignature();
        bytes memory expected =
            hex"3046022100bed017bc6f4c80dbffd97ae753b58b597c1b71334de814cd59f482303b29425f022100966d4754727615e27d969afa11a72f95bd92280981dee958f50fce3555578245";
        assertEq(result, expected, "Signature should be serialized correctly");

        sig = anotherMessageHash.sign(anotherPrivateKey);
        result = sig.serializeSignature();
        expected =
            hex"304402203bb237e75196b68bec2c415c2efde31364557a50681df03bbc1b6bd3dfcb4d4602203a3ec12e15d72a071b042a4e59cf52ec4f5b2fc664d3ff5f82be08c32e2d4553";
        assertEq(result, expected, "Another signature should be serialized correctly");
    }

    function test_parseSignature() public view {
        Signature memory sig = messageHash.sign(privateKey);
        bytes memory sigSerial = sig.serializeSignature();
        Signature memory result = sigSerial.parseSignature();
        assertEq(result.r, sig.r, "Wrong signature r");
        assertEq(result.s, sig.s, "Wrong signature s");

        sig = messageHash.sign(anotherPrivateKey);
        sigSerial = sig.serializeSignature();
        result = sigSerial.parseSignature();
        assertEq(result.r, sig.r, "Wrong another signature r");
        assertEq(result.s, sig.s, "Wrong another signature s");
    }

    function test_fuzz_parseSignature(uint256 _privateKey) public view {
        Signature memory sig = messageHash.sign(_privateKey);
        Signature memory result = sig.serializeSignature().parseSignature();
        assertEq(result.r, sig.r, "Wrong signature r");
        assertEq(result.s, sig.s, "Wrong signature s");
    }

    function test_serializeTransaction() public view {
        for (uint256 i; i < rawTxs.length; ++i) {
            assertEq(rawTxs[i].parseTransaction().serializeTransaction(), rawTxs[i], "Wrong serialized transaction");
        }
    }

    function test_parseTransaction() public view {
        Transaction memory resTx = rawTxs[0].parseTransaction();
        assertFalse(resTx.isSegwit, "Wrong isSegwit 0");
        assertEq(resTx.version, hex"00000001", "Wrong version 0");
        assertEq(resTx.inputs.length, 1, "Wrong number of inputs 0");
        assertEq(
            resTx.inputs[0].txId, hex"59ea4c177b629fab711c50526acfba6a9e90fccab0f5b6091106da74a73e3030", "Wrong txId 0"
        );
        assertEq(resTx.inputs[0].vout, hex"00000001", "Wrong vout 0");
        assertEq(
            resTx.inputs[0].scriptSig,
            hex"0047304402203285484f30722560cfd2c8f346c58be14791ac2859b9ef5aebd31373b9d9ed3802202a40bf31a4a297ba3130920707a2d5315019f33cd175270c198e81727460c96401473044022001888d61eb5d3d5528098531a7dbdb5233748712f069f022a2135e6175bb66a9022064860cb4fb71c3879dce3835765b7f76dbf35621f55729b8c69623e55d13811f01475221022b6dc4281a12a37a00ab920fd9ab1d4b509e288122cf406cd3d0bfb2f5471706210392e4ecdd0af74a2d05b9448343b22fac173c1618c62caf2039efb09c7e67f2d452ae",
            "Wrong scriptSig 0"
        );
        assertEq(resTx.inputs[0].sequence, hex"ffffffff", "Wrong sequence 0");
        assertEq(resTx.outputs.length, 2, "Wrong number of outputs 0");
        assertEq(resTx.outputs[0].amount, hex"00000000034985b0", "Wrong amount 0 at 0");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"a914b4eef9a952db30866728f788bb469bae8d5fc52687",
            "Wrong scriptPubKey 0 at 0"
        );
        assertEq(resTx.outputs[1].amount, hex"000000003787dfd5", "Wrong amount 0 at 1");
        assertEq(
            resTx.outputs[1].scriptPubKey,
            hex"a91483e02ab859c6ab1e4ee45b20492eaca173f0b6fb87",
            "Wrong scriptPubKey 0 at 1"
        );
        assertEq(resTx.witness.length, 0, "Wrong number of witnesses 0");
        assertEq(resTx.locktime, hex"00000000", "Wrong locktime 0");

        resTx = rawTxs[1].parseTransaction();
        assertFalse(resTx.isSegwit, "Wrong isSegwit 1");
        assertEq(resTx.version, hex"00000001", "Wrong version 1");
        assertEq(resTx.inputs.length, 1, "Wrong number of inputs 1");
        assertEq(
            resTx.inputs[0].txId, hex"0000000000000000000000000000000000000000000000000000000000000000", "Wrong txId 1"
        );
        assertEq(resTx.inputs[0].vout, hex"ffffffff", "Wrong vout 1");
        assertEq(resTx.inputs[0].scriptSig, hex"04bedf061a02d405062f503253482f", "Wrong scriptSig 1");
        assertEq(resTx.inputs[0].sequence, hex"ffffffff", "Wrong sequence 1");
        assertEq(resTx.outputs.length, 1, "Wrong number of outputs 1");
        assertEq(resTx.outputs[0].amount, hex"000000012a05f200", "Wrong amount 1");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"410450d5ef5bb3d8a893a4b1fcf2e9d8f898d782fbf22a887f3fbafd22b06d225a5754be9b2cd0d00ee2c3715bfced2e403a6e0d1bf2716ebfd6e6f9ddac1924b6e7ac",
            "Wrong scriptPubKey 1"
        );
        assertEq(resTx.witness.length, 0, "Wrong number of witnesses 1");
        assertEq(resTx.locktime, hex"00000000", "Wrong locktime 1");

        resTx = rawTxs[2].parseTransaction();
        assertFalse(resTx.isSegwit, "Wrong isSegwit 2");
        assertEq(resTx.version, hex"00000001", "Wrong version 2");
        assertEq(resTx.inputs.length, 3, "Wrong number of inputs 2");
        assertEq(
            resTx.inputs[0].txId,
            hex"673377e8bdaef24a9e26113a5a82a37e1fd217ea9b3b76dd203ba3d948176b5f",
            "Wrong txId 2 at 0"
        );
        assertEq(resTx.inputs[0].vout, hex"00000000", "Wrong vout 2 at 0");
        assertEq(
            resTx.inputs[0].scriptSig,
            hex"493046022100ed23c8cbb485acd3c073137803584b2a2c91f350d17b54bd1a10a4b814dfad44022100a567ba44f3a3b0769ae96b9af42f4a33827eaa92f5c40deb5886e0009a70f39d012102e2d7f7486ced79f3a4fcc26e4848bd2de484397ba8df365d468acbeecd3562b8",
            "Wrong scriptSig 2 at 0"
        );
        assertEq(resTx.inputs[0].sequence, hex"ffffffff", "Wrong sequence 2 at 0");
        assertEq(
            resTx.inputs[1].txId,
            hex"6669576110b88393deee856787cdbbe83834d2b363564419e275319080afbbd7",
            "Wrong txId 2 at 1"
        );
        assertEq(resTx.inputs[1].vout, hex"00000000", "Wrong vout 2 at 1");
        assertEq(
            resTx.inputs[1].scriptSig,
            hex"483045022100e7ad48a20853c7cc1f419589407173b5e82c37e5715f7bc08ed6682381b0adcc0220200ec21da4a684f870bc8065f8a92e669421ca4c747278cc7a0aa5ad44b6555401210342dd1c67748c439ba4567a325c842caa3a16ba5200e730c47af2e5aa581903ed",
            "Wrong scriptSig 2 at 1"
        );
        assertEq(resTx.inputs[1].sequence, hex"ffffffff", "Wrong sequence 2 at 1");
        assertEq(
            resTx.inputs[2].txId,
            hex"3c0eca15277372b8f7c7204a344e727fb9f61bfe29cabbd231c3cc4d9ffffba9",
            "Wrong txId 2 at 2"
        );
        assertEq(resTx.inputs[2].vout, hex"00000000", "Wrong vout 2 at 2");
        assertEq(
            resTx.inputs[2].scriptSig,
            hex"483045022100b473b18f9942a9097e5e8677fd4c0442458c193770a65de258928c9f1d9478e902201f41799ef679577fdf0b2783962d1f64da1f828d994991afdff5465bfd8970e9012102f14306fcfc9a8138cc86469c5d2b40f28d885a19faf45b2be6578ea10e910252",
            "Wrong scriptSig 2 at 2"
        );
        assertEq(resTx.inputs[2].sequence, hex"ffffffff", "Wrong sequence 2 at 2");
        assertEq(resTx.outputs.length, 2, "Wrong number of outputs 2");
        assertEq(resTx.outputs[0].amount, hex"0000000017d78400", "Wrong amount 2 at 0");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"76a914f5bc94a48ad7f290c58b4fb970514cbf99daf30b88ac",
            "Wrong scriptPubKey 2 at 0"
        );
        assertEq(resTx.outputs[1].amount, hex"00000000000f4247", "Wrong amount 2 at 1");
        assertEq(
            resTx.outputs[1].scriptPubKey,
            hex"76a914f094dc8e530cdc17221fc936399fcf0da5c3cb4a88ac",
            "Wrong scriptPubKey 2 at 1"
        );
        assertEq(resTx.witness.length, 0, "Wrong number of witnesses 2");
        assertEq(resTx.locktime, hex"00000000", "Wrong locktime 2");

        resTx = rawTxs[3].parseTransaction();
        assertTrue(resTx.isSegwit, "Wrong isSegwit 3");
        assertEq(resTx.version, hex"00000002", "Wrong version 3");
        assertEq(resTx.inputs.length, 1, "Wrong number of inputs 3");
        assertEq(
            resTx.inputs[0].txId, hex"159d5ede9a4d73e574d6a5a62cbd41a25e4628296bcb241fca355aa07080acef", "Wrong txId 3"
        );
        assertEq(resTx.inputs[0].vout, hex"00000000", "Wrong vout 3");
        assertEq(resTx.inputs[0].scriptSig, hex"160014a5b404e24cfc890850c410b0c4aa266d021b1125", "Wrong scriptSig 3");
        assertEq(resTx.inputs[0].sequence, hex"fffffffd", "Wrong sequence 3");
        assertEq(resTx.outputs.length, 2, "Wrong number of outputs 3");
        assertEq(resTx.outputs[0].amount, hex"000000000017cdc0", "Wrong amount 3 at 0");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"76a914d8e2f29deeb25460da0543c4baf0a43591d3584a88ac",
            "Wrong scriptPubKey 3 at 0"
        );
        assertEq(resTx.outputs[1].amount, hex"000000000234e5bf", "Wrong amount 3 at 1");
        assertEq(
            resTx.outputs[1].scriptPubKey,
            hex"a914aa28aaf1b7949dc848d025434c0ef3cc152738f487",
            "Wrong scriptPubKey 3 at 1"
        );
        assertEq(resTx.witness.length, 1, "Wrong number of witnesses 3");
        assertEq(
            resTx.witness[0][0],
            hex"304402205c96b8cf7f64a49bea1950f124dd078741d0eb4b9db37a4e0a87ffa9760e5e4b0220165d6a90848743246b42e4b4e46966d777f26fcb5404517177ab840d2518ab8501",
            "Wrong witness 3 at 0"
        );
        assertEq(
            resTx.witness[0][1],
            hex"03ed4a30070a474a35eda68c1dd71fc7db3aa646a5e80b43d666d27d59adcb856a",
            "Wrong witness 3 at 1"
        );
        assertEq(resTx.locktime, hex"0009508e", "Wrong locktime 3");

        resTx = rawTxs[4].parseTransaction();
        assertTrue(resTx.isSegwit, "Wrong isSegwit 4");
        assertEq(resTx.version, hex"00000001", "Wrong version 4");
        assertEq(resTx.inputs.length, 2, "Wrong number of inputs 4");
        assertEq(
            resTx.inputs[0].txId,
            hex"6fc6d85728f9fff517c579f4b1407c29604f1c80a89341dd55803cf310829099",
            "Wrong txId 4 at 0"
        );
        assertEq(resTx.inputs[0].vout, hex"00000002", "Wrong vout 4 at 0");
        assertEq(
            resTx.inputs[0].scriptSig,
            hex"4730440220618d6a5b0e9758e6a18ee4eb2737fbce220745658d9bea3f145408b67e83f7af02205915852662634783220ed58370b984081e6b0abdbcd2caeec9a72f19f1a5ddd101210326efb2708b4e0e1950706a4d7cbaa063ed2aa32afbedc5793a533a723f767fbe",
            "Wrong scriptSig 4 at 0"
        );
        assertEq(resTx.inputs[0].sequence, hex"ffffffff", "Wrong sequence 4 at 0");
        assertEq(
            resTx.inputs[1].txId,
            hex"0b280c7f2a6eab0eb65e9ed4519f64ff851df28cdd9ba0efa1e0efa01e85b41f",
            "Wrong txId 4 at 1"
        );
        assertEq(resTx.inputs[1].vout, hex"00000001", "Wrong vout 4 at 1");
        assertEq(
            resTx.inputs[1].scriptSig, hex"16001470c79be6d74420b7920dca35849cb5a37e2e60be", "Wrong scriptSig 4 at 1"
        );
        assertEq(resTx.inputs[1].sequence, hex"ffffffff", "Wrong sequence 4 at 1");
        assertEq(resTx.outputs.length, 4, "Wrong number of outputs 4");
        assertEq(resTx.outputs[0].amount, hex"0000000000000000", "Wrong amount 4 at 0");
        assertEq(
            resTx.outputs[0].scriptPubKey,
            hex"6a146f6d6e69000000000000001f000000912571427c",
            "Wrong scriptPubKey 4 at 0"
        );
        assertEq(resTx.outputs[1].amount, hex"00000000000a4ef3", "Wrong amount 4 at 1");
        assertEq(
            resTx.outputs[1].scriptPubKey,
            hex"a91438a9ee60e46a957475e429585dc63bb6fd84dd2887",
            "Wrong scriptPubKey 4 at 1"
        );
        assertEq(resTx.outputs[2].amount, hex"0000000000000222", "Wrong amount 4 at 2");
        assertEq(
            resTx.outputs[2].scriptPubKey,
            hex"76a914e3d41f555febacef735148156e7f3ce866d0a00188ac",
            "Wrong scriptPubKey 4 at 2"
        );
        assertEq(resTx.outputs[3].amount, hex"0000000000000222", "Wrong amount 4 at 3");
        assertEq(
            resTx.outputs[3].scriptPubKey,
            hex"76a9148b9237e241576595d294c07a793847fd2b628b8088ac",
            "Wrong scriptPubKey 4 at 3"
        );
        assertEq(resTx.witness.length, 2, "Wrong number of witnesses 4");
        assertEq(resTx.witness[0].length, 0, "Wrong number of witnesses 4 at 0");
        assertEq(resTx.witness[1].length, 2, "Wrong number of witnesses 4 at 1");
        assertEq(
            resTx.witness[1][0],
            hex"304402205c2441e0feb05bba4890d28bd95449c2a3d26703af552f84d4a272815e25cd6b022068eb6f6acdd7652ea0fc2796d56aa2e7a4347497e05159d90acd0c775cff31b101",
            "Wrong witness 4 at 1, 0"
        );
        assertEq(
            resTx.witness[1][1],
            hex"02a879a0629b5c6cbdba08f41601ad331e1e100961b19e6396e76a576acdb8ce33",
            "Wrong witness 4 at 1, 1"
        );
        assertEq(resTx.locktime, hex"00000000", "Wrong locktime 4");
    }

    function test_serializeBlock() public view {
        for (uint256 i; i < rawBlocks.length; ++i) {
            assertEq(rawBlocks[i].parseBlock().serializeBlock(), rawBlocks[i], "Wrong serialized block");
        }
    }

    function test_parseBlock() public view {
        Block[5] memory expected = [
            Block({
                version: 0x00000001,
                prevBlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
                merkleRoot: 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b,
                timestamp: 0x495fab29,
                bits: 0x1d00ffff,
                nonce: 0x7c2bac1d,
                transactionHashes: new bytes32[](0)
            }),
            Block({
                version: 0x00000001,
                prevBlock: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f,
                merkleRoot: 0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098,
                timestamp: 0x4966bc61,
                bits: 0x1d00ffff,
                nonce: 0x9962e301,
                transactionHashes: new bytes32[](0)
            }),
            Block({
                version: 0x2170a000,
                prevBlock: 0x00000000000000000004d5185fddf13fec4b23c80ba86ef9b86e9170e7966458,
                merkleRoot: 0x143e001843ce39245bff7b02b199b1c1458e89aa3927d6812d562ab32a57eece,
                timestamp: 0x6458f163,
                bits: 0x1705dd01,
                nonce: 0x7c320903,
                transactionHashes: new bytes32[](0)
            }),
            Block({
                version: 0x20c00000,
                prevBlock: 0x0000000000000000000d6ae7c6aedbc339d7a38b2512d1c639c661cdb03fe95f,
                merkleRoot: 0x0751a71596fb9a28ce37bfddc0ed712d27275aa0d8a546dac7a1fc1134c9a30b,
                timestamp: 0x5fca2c62,
                bits: 0x170eb156,
                nonce: 0x795fc41c,
                transactionHashes: new bytes32[](0)
            }),
            Block({
                version: 0x3fffe000,
                prevBlock: 0x00000000000000000007ae68e52b695946642db2bacfc1e821b5a065189b98cf,
                merkleRoot: 0xbd15e7f44c8ab83e5117cae8637e99496dbaf990a981959e2bd8ea2639bbf0d9,
                timestamp: 0x5efaad49,
                bits: 0x1711d4f2,
                nonce: 0xc526460e,
                transactionHashes: new bytes32[](2)
            })
        ];
        expected[4].transactionHashes[0] = 0x4ac4835d7df06e229f02990cb658952f36ca9cd7729de3431be781b96a458185;
        expected[4].transactionHashes[1] = 0x4e50d20bd5faf145c4e2fe588ac69a1140a127687526668f4fc88108840bd361;

        Block memory res;
        for (uint256 i; i < rawBlocks.length; ++i) {
            res = rawBlocks[i].parseBlock();
            assertEq(res.version, expected[i].version, "Wrong version");
            assertEq(res.prevBlock, expected[i].prevBlock, "Wrong prevBlock");
            assertEq(res.merkleRoot, expected[i].merkleRoot, "Wrong merkleRoot");
            assertEq(res.timestamp, expected[i].timestamp, "Wrong timestamp");
            assertEq(res.bits, expected[i].bits, "Wrong bits");
            assertEq(res.nonce, expected[i].nonce, "Wrong nonce");
            assertEq(
                res.transactionHashes.length, expected[i].transactionHashes.length, "Wrong transactionHashes length"
            );
            if (res.transactionHashes.length > 0) {
                for (uint256 j; j < res.transactionHashes.length; ++j) {
                    assertEq(res.transactionHashes[j], expected[i].transactionHashes[j], "Wrong transactionHash");
                }
            }
        }
    }
}
