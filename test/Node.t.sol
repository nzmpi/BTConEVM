// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {Script} from "../src/Script.sol";
import {SerialLib} from "../src/lib/SerialLib.sol";
import "../src/lib/Structs.sol";
import {Node} from "../src/Node.sol";
import "../src/lib/Utils.sol";

contract MockNode is Node(new Script()) {
    function addUTXO(bytes32 txId, bytes4 vout) external {
        UTXOs[txId][vout] = true;
    }

    function addTransaction(bytes32 txId, Transaction calldata transaction) external {
        transactions[txId] = transaction;
    }
}

contract TestNode is BaseTest {
    using SerialLib for *;
    using Utils for *;

    bytes4 constant SIGHASH_ALL = 0x01000000;
    MockNode mock;

    function setUp() public {
        mock = new MockNode();
    }

    function test_validate_P2PKH() public {
        // https://btcscan.org/tx/44f76b52d6b5c9d2e3ebd0a9edb4fa551743cd97d8e8f23171247e64cae12f5b
        TxInput[] memory inputs = new TxInput[](1);
        inputs[0].txId = hex"ffb7105241405f30849cfa7d3be277d5f4da62c4f45d96df26116fecae4e6ceb";
        inputs[0].vout = bytes4(uint32(3));
        inputs[0].scriptSig =
            hex"4830450221009860646b4f663628853ec357b8d364b75e6c1cdf6138471fa74ada8c86edeb2502201a6c6728241c04abfedd62b6e497edcb39a6b01061fc54c5f3f115398704d280012102108c91bbb9473d6b8a1f14cc99a8f34ba361f73fbfac3b8a660c6c4d654a4129";
        inputs[0].sequence = 0xffffffff;

        TxOutput[] memory outputs = new TxOutput[](1);
        outputs[0].amount = bytes8(uint64(0));
        outputs[0].scriptPubKey = hex"6a245336ba7c125fd0e2bf432f2379eb849d6906c4adb9e1713ff2058c76c12ef50e1e07ac75";

        Transaction memory transaction =
            Transaction({version: 0x00000001, inputs: inputs, outputs: outputs, locktime: 0});

        _addPrevTx(inputs[0].txId, inputs[0].vout, 30000, hex"76a9144904d699fbdb22b2b8e240aa31153c26fbe606a088ac");

        mock.validate(transaction, new bytes[](1));
        bytes32 txId = hex"44f76b52d6b5c9d2e3ebd0a9edb4fa551743cd97d8e8f23171247e64cae12f5b";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }

        // https://btcscan.org/tx/a6a0c1bd11c35039b74b1d50e498a1c4f02bd4e8480da35ccf9d0bac2ef7547c
        inputs = new TxInput[](5);
        inputs[0].txId = hex"162221aa810d22a9d085295932668d3b683cec3631d672d4419788855ecb7f93";
        inputs[0].scriptSig =
            hex"47304402206d1539ad8d6578c3a1d22b751fd1a327f1f68b326d44ba967544fee2ef410f12022011d37bb291901ab009a6a36df892fad27a4e255eb15365e786754ce03863ce79014104606bf18bd8b5994b1e37ce13e7eed33e8508234a40d8795cfa6fe1f875c7e7eea13d31dc6fc77d2cc02880a9848d1573005d246a7a215b6b1ef48f7296a9d0b3";
        inputs[1].txId = hex"d8c6a0879264cef0aecaf16e5ca7714ca072c0c47c01179e17fbaf15c1183ab2";
        inputs[1].scriptSig =
            hex"483045022100e2965624e05cb5a1a3f15003b415a6f1848b3df56d59b236fa1de2077b2d49030220269d1514a8a7e67d51e602fb884a9d17dace07073104b9f81537207ed139e00d01410473fcf10c42433b808612b5719f347b6b9919f21dbcd5c333ae9383291c7e401330efc14ba0eddda431160ebd4bc2a273eddc66c27f34e9ae11ad6cce949dbcb1";
        inputs[2].txId = hex"ee494cdaeeee5257518ed7da8e1169ee865f9919bd5a40296971e9ea99d63671";
        inputs[2].scriptSig =
            hex"47304402202fa668cea969bb0c9adb972e0633c73c6f0a4fe1b82e7a61db80f2a697da941b022012dae0fdfb99a54f04e1af3441d31b58c81393cc8ef39c168027375a16250c340141043442d20bafeb59b9d59e2f5ab62c71f5e2f8c66d415b66f578e360dbf0af117eb82dbdb5c606ebba65e33f5dfa3dfadf4e65aeacc931f041386d03b0156481cf";
        inputs[3].txId = hex"c982385ba9f9cd0a0b14051efe878102adca46773b696095bbd0cd7ad2396d0f";
        inputs[3].scriptSig =
            hex"47304402207555fe46731a6ced964ca806bdd98d0cda3868315b7a0c56d7ad515d2d5fae81022077a66b16857fb5a34da70d154ef4c46ab598e85c4453e98df2e90c9abb3e39450141047c635dc080293c3c67aa9f1ee53f3b1dac418b3ca4140645332481bafe977586ad77f2fc7c2f436ed79671fceed4d56c4f80dc4e7ac5cdea412085a608dd75d7";
        inputs[4].txId = hex"40bf2b3611b864996f406b52f320901b2d0e1d5fc83c3b701bf81150c3039c99";
        inputs[4].scriptSig =
            hex"483045022100e863d19a4e8b7a8d368030d4dfbab40d1153a17b3bcf514b00b7f3cd0ef653e7022050a8ad27bc66a4c137a8f49c0058bfa976176e8667611e6868235eba81c9d17c0141041d6f75688bb01c2ff934e484723c224babb466d20666e0368f236ef7cc63903274aa8bd12777083c14e35c4845aa86a7d9fe79370c9c8389b05eb3ede347996b";
        for (uint256 i; i < inputs.length; ++i) {
            inputs[i].vout = bytes4(uint32(1));
            inputs[i].sequence = 0xffffffff;
        }

        outputs = new TxOutput[](2);
        outputs[0].amount = bytes8(uint64(19836425));
        outputs[0].scriptPubKey = hex"76a91438389756a60900dadb47590bcade162452dc0b5888ac";
        outputs[1].amount = bytes8(uint64(39708114));
        outputs[1].scriptPubKey = hex"76a914f8678d7aad9730afe575e4a8e51abfd44a510b8088ac";

        transaction = Transaction({version: 0x00000001, inputs: inputs, outputs: outputs, locktime: 0});

        _addPrevTx(inputs[0].txId, inputs[0].vout, 10000000, hex"76a91406f1b6703d3f56427bfcfd372f952d50d04b64bd88ac");
        _addPrevTx(inputs[1].txId, inputs[1].vout, 9909107, hex"76a91435508d36cd1919a9588a08bcb9db534b266f6c7e88ac");
        _addPrevTx(inputs[2].txId, inputs[2].vout, 9909107, hex"76a914f46e29212bb165a28993b8109bd0472e0345310c88ac");
        _addPrevTx(inputs[3].txId, inputs[3].vout, 9909107, hex"76a9149d56e762a05ffb6dd15da63672b0e8a1309469c088ac");
        _addPrevTx(inputs[4].txId, inputs[4].vout, 19867218, hex"76a914d4944c48a58a161b898bea6144721e77858a1e3288ac");

        mock.validate(transaction, new bytes[](5));
        txId = hex"a6a0c1bd11c35039b74b1d50e498a1c4f02bd4e8480da35ccf9d0bac2ef7547c";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
    }

    function test_validate_P2SH() public {
        // https://btcscan.org/tx/c7903b511d301cebae89c8e1eb9a521f742607015044430d5eef2656e88410f2
        TxInput[] memory inputs = new TxInput[](1);
        inputs[0].txId = hex"b5336475543fb8ffc95783eab71c3eb7153b99f12966fbf42662509b3839adc7";
        inputs[0].vout = bytes4(uint32(5));
        inputs[0].scriptSig =
            hex"0047304402204dab7915f97573c9860ecd1554c1b38a507e86756cefd9111cc845f5e404fe6d02206c312e43994277a844f082b83029abb0e0581e053143f1c1ada948ca01701684014730440220110600da2e488285fd4e1d6278760e513ef8d70e3eb500ef75004162eb3da86f02205af6af366d4084b22d043e9ed6c6a54a62f0e24886df87dbb62281d1596d36d1014c6952210330cd0f60c8093b34fcb69d6159be3a942f33560d138d68d277694b0b960f18c52102e3713ed176faff1478aee9ef28147a4b4d99b6ab01612514de9786b388e2d191210314d42df81081b7a871ad950bd0b715cf9ab0f4da576692f18c46701db266636f53ae";
        inputs[0].sequence = 0xffffffff;

        TxOutput[] memory outputs = new TxOutput[](1);
        outputs[0].amount = bytes8(uint64(35560));
        outputs[0].scriptPubKey = hex"76a914b1df5abd0a71b36e02a8bde3a14b2f9083f8c9fd88ac";

        Transaction memory transaction =
            Transaction({version: 0x00000001, inputs: inputs, outputs: outputs, locktime: 0});

        _addPrevTx(inputs[0].txId, inputs[0].vout, 36259, hex"a9149678efcda8681c0e1b807b8b094a1f96a87c5bd087");

        bytes[] memory redeemScript = new bytes[](1);
        redeemScript[0] =
            hex"52210330cd0f60c8093b34fcb69d6159be3a942f33560d138d68d277694b0b960f18c52102e3713ed176faff1478aee9ef28147a4b4d99b6ab01612514de9786b388e2d191210314d42df81081b7a871ad950bd0b715cf9ab0f4da576692f18c46701db266636f53ae";
        mock.validate(transaction, redeemScript);
        bytes32 txId = hex"c7903b511d301cebae89c8e1eb9a521f742607015044430d5eef2656e88410f2";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());

        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }

        // https://btcscan.org/tx/9d3c6335e0dd47c3fff78649b474936fa001046b61aab8fcfd002750403dc4e3
        inputs = new TxInput[](3);
        inputs[0].txId = hex"f8f4cfb56430806ef86aea4bf2f19b289793e2c343d69277786537b33bee5b9d";
        inputs[0].scriptSig =
            hex"004830450221008f4c5099403b55cd2b8d02ad4ce04b6592658b4680a898d8db21aa952d9237c50220665c579c2bcf8c73d05b1cc48e6e68c3bc55ca9cb621440eb35316a98c463f5601473044022051b0b05081ebec30f71addf9b02731832e8b49cd809ab2fb52938ace48c9517202204f6b062519c1683a11e37ea72025a29af2040ee08f9f57d6e8cbf6ca944443ad0147522102e62f36e97d9bd036e07d5f2e2afcb77755f28196eb2d4f52f6ab37174309475521024c7c6f60a83750ad68c08ac812b77dbbf0c295772e0c9ea9b38639874bb4323552ae";
        inputs[1].txId = hex"39863ea2c38943c0a64c79677056cf4d713083588fee568d0f4f926ec072ee17";
        inputs[1].scriptSig =
            hex"00483045022100e5930d98594462bf5c53f8fb165301b719e8a9ac13c86e16f400c31d3d90080802207f33c9cce341c6453237edc6ee0d192bba5124a90450fae4ab9d7d38b6f7ef7f0147304402205fe21563a6cc00bd09924de98ebc9514c24cb63a4bab4b35af15840d02c2b9cf02201819ddef49f68fcb37f6b4d531f48259114e17b9f3fc1f0819ae2f0126fe194e0147522102c3cf6b57cfc145a0b7ce22d019b5e8ae1fec350d52e8fec5a8a4a9b3046e8f6221024c7c6f60a83750ad68c08ac812b77dbbf0c295772e0c9ea9b38639874bb4323552ae";
        inputs[2].txId = hex"5691e3f696dfb4c5fe052119590265ce5b24949cf811100253dd7e8fb93aee8b";
        inputs[2].scriptSig =
            hex"00483045022100ccd46f55611ec26d6b77a80d36aef43a2e8a050207e79d5e30b585e7aa94f58702201dee3d4c9a7d7dd3e4f6a5c77aa70e7109ece201cea22f6847ddfca979ddac78014830450221008147696d6634b88d80b6d298c251a5aef90fa3f3cd867cd43b4960ae6802215302204af9c835a79f3726c6cc7fd9d93ffc0337f72ffe48ce2eaaf15afb56062672e101475221035edb569f25e3b0d215e0b803828c4b503f7a5ca1fec5b46513f07da3d4ce295321024c7c6f60a83750ad68c08ac812b77dbbf0c295772e0c9ea9b38639874bb4323552ae";
        for (uint256 i; i < inputs.length; ++i) {
            inputs[i].vout = bytes4(uint32(1));
            inputs[i].sequence = 0xffffffff;
        }

        outputs = new TxOutput[](2);
        outputs[0].amount = bytes8(uint64(2991287));
        outputs[0].scriptPubKey = hex"76a914b2a876a1b1099c2d4f7fa23056c1e8f4dfd1a67088ac";
        outputs[1].amount = bytes8(uint64(182453783));
        outputs[1].scriptPubKey = hex"a9140fda2d6bce7644a53bfd80c49c14286df1fa376a87";

        transaction = Transaction({version: 0x00000001, inputs: inputs, outputs: outputs, locktime: 0});

        _addPrevTx(inputs[0].txId, inputs[0].vout, 131259, hex"a91433275b5570d4a73c43ea9373d09c6d4fbe30213c87");
        _addPrevTx(inputs[1].txId, inputs[1].vout, 12320, hex"a9147862c6014f8054b8f712af5eebcbcba97943fbca87");
        _addPrevTx(inputs[2].txId, inputs[2].vout, 185351491, hex"a9140fda2d6bce7644a53bfd80c49c14286df1fa376a87");

        redeemScript = new bytes[](3);
        redeemScript[0] =
            hex"522102e62f36e97d9bd036e07d5f2e2afcb77755f28196eb2d4f52f6ab37174309475521024c7c6f60a83750ad68c08ac812b77dbbf0c295772e0c9ea9b38639874bb4323552ae";
        redeemScript[1] =
            hex"522102c3cf6b57cfc145a0b7ce22d019b5e8ae1fec350d52e8fec5a8a4a9b3046e8f6221024c7c6f60a83750ad68c08ac812b77dbbf0c295772e0c9ea9b38639874bb4323552ae";
        redeemScript[2] =
            hex"5221035edb569f25e3b0d215e0b803828c4b503f7a5ca1fec5b46513f07da3d4ce295321024c7c6f60a83750ad68c08ac812b77dbbf0c295772e0c9ea9b38639874bb4323552ae";
        mock.validate(transaction, redeemScript);
        txId = hex"9d3c6335e0dd47c3fff78649b474936fa001046b61aab8fcfd002750403dc4e3";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
    }

    function test_validate_mixed() public {
        // https://btcscan.org/tx/f228eda842bd635511ae6f4b4b24cc74cc03d385231d10d1d69b15db1442e6db
        TxInput[] memory inputs = new TxInput[](2);
        inputs[0].txId = hex"bfd9c92cde92d9cb27bb2a91ccdf8d1507152541b26c4e4ad238014ade7c330c";
        inputs[0].vout = bytes4(uint32(0));
        inputs[0].scriptSig =
            hex"00483045022100dedf931c7b69905661a15fe795f70408ad58ec9318c6460fa6f2face868af2e102206241da82d18582628d3d826ea0ed469959fbb999979cff17d80d59bd9ace06b3014730440220613d2a4400cb67ba342f11e6e7053d5df73eecf0c1d08fd0206742291147a02502204e192c8933d6a2fe9ef9cdcf3c644ec55367540721d19c87f722c483bb0cb51f0147522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b612103bc94de59cdfdf34c1b1977570ec1d6cd73532323d6d7cf9ae1418d5c0144ee6652ae";
        inputs[0].sequence = 0xffffffff;
        inputs[1].txId = hex"6f67eabf9220d9af0275db0dd2e0398249d1be7a6e15051f3bb648eb823f8727";
        inputs[1].vout = bytes4(uint32(2));
        inputs[1].scriptSig =
            hex"47304402205f24da490d89a31b753a8b3e7b24c0d3b0f9124552e666d8578e8dd3fe029ae40220479f932d1ea955eafd658bff3878e7354d5e6c154d688aa043bfcb2c7cb8aad601210207d344596cc0883990b0137c0a7534920211278948a64397a9cf1584a8484f97";
        inputs[1].sequence = 0xffffffff;

        TxOutput[] memory outputs = new TxOutput[](3);
        outputs[0].amount = bytes8(uint64(98522146));
        outputs[0].scriptPubKey = hex"a9141199b83ec2069d16bd075f9b43f4e4cfedc4f09787";
        outputs[1].amount = bytes8(uint64(7906847));
        outputs[1].scriptPubKey = hex"a91470d6baffab240bece5d74698dadc39b7649b3a2887";
        outputs[2].amount = bytes8(uint64(122747));
        outputs[2].scriptPubKey = hex"76a914becac737c973aab0e5530c611b9ac39b582d38c288ac";

        Transaction memory transaction =
            Transaction({version: 0x00000001, inputs: inputs, outputs: outputs, locktime: 0});

        _addPrevTx(inputs[0].txId, inputs[0].vout, 98500024, hex"a91462e5205f71ff7146044c73c6ae0f1710bdcf519987");
        _addPrevTx(inputs[1].txId, inputs[1].vout, 8061624, hex"76a914b568d34f957022f79e6f6b6980ddf289b1532ec188ac");

        bytes[] memory redeemScript = new bytes[](2);
        redeemScript[0] =
            hex"522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b612103bc94de59cdfdf34c1b1977570ec1d6cd73532323d6d7cf9ae1418d5c0144ee6652ae";
        redeemScript[1] = hex"";
        mock.validate(transaction, redeemScript);
        bytes32 txId = hex"f228eda842bd635511ae6f4b4b24cc74cc03d385231d10d1d69b15db1442e6db";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
    }

    function test_invalid_validate() public {
        TxInput[] memory inputs = new TxInput[](0);
        TxOutput[] memory outputs = new TxOutput[](0);
        Transaction memory transaction =
            Transaction({version: 0x00000001, inputs: inputs, outputs: outputs, locktime: 0});
        // no inputs
        vm.expectRevert(Node.InvalidTxInputs.selector);
        mock.validate(transaction, new bytes[](1));

        // https://btcscan.org/tx/1a155aef7214fa8b01a19fa1e267acf1b551f5d88afa20e0b50cf5ea0a1d6a68
        inputs = new TxInput[](1);
        inputs[0].txId = hex"9cb5776171e603028725f0b6ae4211593cd36507295a5c403c72179f0f4d6e84";
        inputs[0].vout = bytes4(uint32(1));
        inputs[0].scriptSig =
            hex"483045022100f808708a72d92e42647bd7c801d437bf82a29dd1880457c6e0967240f40089e0022034af63b6d3693d97bdf739aa967b8977127a48caca7389927029864eab9cd69d012102c9fb474d76a1f24abc3ff138acac75d5074e397841305e899540069ff044f00c";
        inputs[0].sequence = 0xffffffff;

        outputs = new TxOutput[](2);
        outputs[0].amount = bytes8(uint64(15564202));
        outputs[0].scriptPubKey = hex"76a914069532d8fec3199b205d1269a3eac85bf55c2fde88ac";
        outputs[1].amount = bytes8(uint64(748138));
        outputs[1].scriptPubKey = hex"76a914ab4aaa0207f7f87db339fdcec70dc82f257bdb4888ac";

        transaction.inputs = inputs;
        transaction.outputs = outputs;

        // no data
        bytes[] memory data = new bytes[](0);
        vm.expectRevert(Node.InvalidTxInputs.selector);
        mock.validate(transaction, data);

        // UTXO is spent
        data = new bytes[](1);
        vm.expectRevert(Node.UTXOisSpent.selector);
        mock.validate(transaction, data);

        // not supported script
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"04ffff001d026809");
        vm.expectRevert(Node.NotSupported.selector);
        mock.validate(transaction, data);

        // invalid P2PKH script
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"76a914069532d8fec3199b205d1269a3eac85bf55c2fde88ac");
        vm.expectRevert(Script.OP_EqualVerifyFailed.selector);
        mock.validate(transaction, data);

        // invalid P2SH script
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"a9149678efcda8681c0e1b807b8b094a1f96a87c5bd087");
        vm.expectRevert(Script.WrongRedeemScriptHash.selector);
        mock.validate(transaction, data);

        // invalid output amount
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"76a914ab4aaa0207f7f87db339fdcec70dc82f257bdb4888ac");
        vm.expectRevert(Node.InvalidFee.selector);
        mock.validate(transaction, data);

        // correct tx
        _addPrevTx(inputs[0].txId, inputs[0].vout, 16322340, hex"76a914ab4aaa0207f7f87db339fdcec70dc82f257bdb4888ac");
        mock.validate(transaction, data);

        // reusing the same tx
        vm.expectRevert(Node.UTXOisSpent.selector);
        mock.validate(transaction, data);
    }

    function _addPrevTx(bytes32 _txId, bytes4 _vout, uint64 _amount, bytes memory _scriptPubKey) internal {
        mock.addUTXO(_txId, _vout);
        TxOutput[] memory outputs = new TxOutput[](uint32(_vout) + 1);
        outputs[uint32(_vout)].amount = bytes8(_amount);
        outputs[uint32(_vout)].scriptPubKey = _scriptPubKey;
        Transaction memory transaction =
            Transaction({version: 0x00000001, inputs: new TxInput[](0), outputs: outputs, locktime: 0});

        mock.addTransaction(_txId, transaction);
    }
}
