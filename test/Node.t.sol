// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Node} from "../src/Node.sol";
import {Script} from "../src/Script.sol";
import {SerialLib} from "../src/lib/SerialLib.sol";
import "../src/lib/Structs.sol";
import "../src/lib/Utils.sol";
import "./utils/BaseTest.sol";

contract MockNode is Node(new Script()) {
    function addUTXO(bytes32 txId, bytes4 vout) external {
        UTXOs[txId][vout] = true;
    }

    function addTransaction(bytes32 txId, Transaction calldata transaction) external {
        _transactions[txId] = transaction;
    }

    function addBlock(uint256 height, Block calldata newBlock) external {
        _blocks[height] = newBlock;
    }

    function validateTx(Transaction calldata _transaction, bytes[] calldata _data) external {
        _validateTx(_transaction, _data);
    }

    function getNewBits(uint256 height) external view returns (bytes4) {
        return _getNewBits(height);
    }

    function getMerkleRoot(bytes32[] calldata _transactionHashes) external pure returns (bytes32) {
        return _getMerkleRoot(_transactionHashes);
    }

    function findNonce(Block calldata _block) external pure returns (bytes4) {
        Block memory res = _block;
        _findNonce(res);
        return res.nonce;
    }

    function addDataForBlock(bytes calldata coinbase, bytes4 blockVersion, bytes4 blockNonce, uint256 currentHeight)
        external
    {
        _coinbase = coinbase;
        _blockVersion = blockVersion;
        _blockNonce = blockNonce;
        _currentHeight = currentHeight;
    }
}

contract TestNode is BaseTest {
    using SerialLib for *;
    using Utils for *;

    MockNode mock;

    function setUp() public {
        mock = new MockNode();
    }

    function test_validate() public {
        // https://btcscan.org/block/0000000032c349b31a64a7cd8cfae3287f2238db0ee82862f31256abdb575da2
        mock.addDataForBlock(
            hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0101ffffffff0100f2052a01000000434104a36b78ae416805c2c04fffc761d1140ebe92add5de8790525a16a6714398ef58c7118f028915db40f1c5ee672b701a5d92ddebdbc47b6b6a0f509de9200fdf0fac00000000",
            hex"00000001",
            hex"ef3f5000",
            20008
        );
        mock.addBlock(
            20007,
            Block({
                version: hex"00000001",
                timestamp: hex"4a67813e",
                bits: hex"1d00ffff",
                nonce: hex"1377e919",
                prevBlock: 0x000000003345e4c22db7cc1ebb84e9db24327f679aad6dd121b0aa12a00e9ccf,
                merkleRoot: 0xb63f086bdf63a9e7b3343a608ad9405c7473b8481e73e0aa19c47dddba7d1fcf,
                transactionHashes: new bytes32[](0)
            })
        );
        vm.warp(0x4a67aa39);
        mock.validate(new Transaction[](0), new bytes[][](0));

        Block memory result = mock.getBlock(20008);
        assertEq(
            result.serializeBlockHeader().hash256().convertEndian(),
            0x0000000032c349b31a64a7cd8cfae3287f2238db0ee82862f31256abdb575da2,
            "Wrong block hash 1"
        );
        assertEq(result.version, hex"00000001", "Wrong version 1");
        assertEq(result.timestamp, hex"4a67aa39", "Wrong timestamp 1");
        assertEq(result.bits, hex"1d00ffff", "Wrong bits 1");
        assertEq(result.nonce, hex"ef3f5623", "Wrong nonce 1");
        assertEq(
            result.prevBlock, 0x00000000bedfbb268d32e50b36ac4d6d5ba70b6912128c592b810321ebff97b3, "Wrong prevBlock 1"
        );
        assertEq(
            result.merkleRoot, 0x504f3058aca2a10f915c6d8d56ac1bc1b59eaf5aa2e727c9535d2699b16d0917, "Wrong merkleRoot 1"
        );
        assertEq(result.transactionHashes.length, 1, "Wrong transactionHashes length 1");

        // https://btcscan.org/block/000000000000be2bc4445d0c929adaa79e6106528b8cc8651f1a0bba37bc0c1b
        mock.addDataForBlock(
            hex"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07045285021b015fffffffff0100f2052a0100000043410447f8203847bdb5a0c9a3a804b9c44cd97dc1ef4b3f0dd3f6804779c342d44180d607aca208a7f00e00fb0a1fd1534ca5a565c3ac58570fd28d087b7fb439d565ac00000000",
            hex"00000001",
            hex"e6312000",
            106848
        );
        mock.addBlock(
            106847,
            Block({
                version: hex"00000001",
                timestamp: hex"4d50ca76",
                bits: hex"1b02fa29",
                nonce: hex"12f75da5",
                prevBlock: 0x000000000000cb6a9c26a0fd328d08e329d6727eb6b4e5d6596777a2ab0ce590,
                merkleRoot: 0x9ad7bc72311ed580ccf0e1455c6c410e9ebfa1ed1b01dde68994bae6eff5de4d,
                transactionHashes: new bytes32[](0)
            })
        );
        mock.addBlock(
            104832,
            Block({
                version: bytes4(0),
                timestamp: hex"4d4129cb",
                bits: hex"1b02fa29",
                nonce: bytes4(0),
                prevBlock: bytes32(0),
                merkleRoot: bytes32(0),
                transactionHashes: new bytes32[](0)
            })
        );
        Transaction[] memory txs = new Transaction[](2);
        TxInput[] memory inputs1 = new TxInput[](2);
        inputs1[0] = TxInput({
            txId: 0x0dcab73b2319700f7b723328bc98c1ff1aa39300c64e56f94fedc99fb4e0f86b,
            vout: bytes4(0),
            scriptSig: hex"48304502201abe08e1eb97725b5135cdc5ef26d303e8040227bcc2fd2538d1457ad55e47940221009f34f24ac38d207c14c201172a97065f3d034eca932bdf5e5e1d8871f3943c1b01",
            sequence: hex"ffffffff"
        });
        inputs1[1] = TxInput({
            txId: 0xc7865a2b832f846a817126a05e90b2c965e57ddbb8e12935b17e97936bfcab71,
            vout: bytes4(0),
            scriptSig: hex"48304502202457d7735274050cb05a8a13d5cc98f5309ef0af047aa1f14e9f5a122da92b45022100bcb728ae9bb5a9151651b6b62a083e4a1d80dbd59e7467bae02f9bff141f026001",
            sequence: hex"ffffffff"
        });
        TxOutput[] memory outputs1 = new TxOutput[](1);
        outputs1[0] = TxOutput({
            amount: bytes8(uint64(10000000000)),
            scriptPubKey: hex"76a914230c14303e435474cf295e677a62480d09dadfa988ac"
        });
        txs[0] = Transaction({
            isSegwit: false,
            version: hex"00000001",
            inputs: inputs1,
            outputs: outputs1,
            locktime: 0,
            witness: new bytes[][](0)
        });
        _addPrevTx(
            inputs1[0].txId,
            inputs1[0].vout,
            5000000000,
            hex"410445f39577af17be31fd7009f8998cd94c9610c4bb0b72621ce339cf7186f1b75d424670b85503b401eab836ac51a215c8da6bbcf4a216cb5fc20257a164e41091ac"
        );
        _addPrevTx(
            inputs1[1].txId,
            inputs1[1].vout,
            5000000000,
            hex"4104a7c39d159b44c3502341238fa412f578180168fff35577407e0632b079c45b1bf82999c59915ca14cf48d4ccecd4b9068c8ea75699e800aecdcf356f6c1b1b6aac"
        );

        TxInput[] memory inputs2 = new TxInput[](1);
        inputs2[0] = TxInput({
            txId: 0xce21f29a1630dd0704ca1ea2aa3e42a3448eb566565aa63c07ebdbd69b23097f,
            vout: bytes4(0),
            scriptSig: hex"47304402207900c36fa843bec52c35c09c28c6db731eeb224c5a300d1790e5bc2afc1ccae2022050785bee736a89c858516ac71ed291fc205e270c8f69035066e5a0f8a1b7c792014104090d5f1037384f61c6318f414b7e705513f93d0e4acbb6bcf6bbcc5e49d8b79b0e6766ec94bd4d00a0ffc78e6476ffe85b13a480e9b2f02e3784a44edd2c0763",
            sequence: hex"ffffffff"
        });
        TxOutput[] memory outputs2 = new TxOutput[](1);
        outputs2[0] = TxOutput({
            amount: bytes8(uint64(5000000)),
            scriptPubKey: hex"76a91478dd3738aff0135ca087261a9fb20103dadc563288ac"
        });
        txs[1] = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs2,
            outputs: outputs2,
            locktime: 0,
            witness: new bytes[][](0)
        });
        _addPrevTx(inputs2[0].txId, inputs2[0].vout, 5000000, hex"76a914492f5a94e2f3708caebf4f61a0fbd535f9f7f27188ac");

        bytes[][] memory data = new bytes[][](2);
        data[0] = new bytes[](2);
        data[1] = new bytes[](1);

        vm.warp(0x4d50cc40);
        mock.validate(txs, data);

        result = mock.getBlock(106848);
        assertEq(
            result.serializeBlockHeader().hash256().convertEndian(),
            0x000000000000be2bc4445d0c929adaa79e6106528b8cc8651f1a0bba37bc0c1b,
            "Wrong block hash 2"
        );
        assertEq(result.version, hex"00000001", "Wrong version 2");
        assertEq(result.timestamp, hex"4d50cc40", "Wrong timestamp 2");
        assertEq(result.bits, hex"1b028552", "Wrong bits 2");
        assertEq(result.nonce, hex"e6312339", "Wrong nonce 2");
        assertEq(
            result.prevBlock, 0x00000000000082648057f14fc835779c6ce46a407bafb2e5c2ac1d20d9f4e822, "Wrong prevBlock 2"
        );
        assertEq(
            result.merkleRoot, 0xd8c1af92e6c693e700977f4c3d68a22de3251a353f31ce6a29e9ae810854163b, "Wrong merkleRoot 2"
        );
        assertEq(result.transactionHashes.length, 3, "Wrong transactionHashes length 2");
    }

    function test_validateTx_P2PK() public {
        // https://btcscan.org/tx/45a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2
        TxInput[] memory inputs = new TxInput[](1);
        inputs[0] = TxInput({
            txId: 0xf5d8ee39a430901c91a5917b9f2dc19d6d1a0e9cea205b009ca73dd04470b9a6,
            vout: bytes4(0),
            scriptSig: hex"48304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501",
            sequence: hex"ffffffff"
        });

        TxOutput[] memory outputs = new TxOutput[](1);
        outputs[0].amount = bytes8(uint64(5000000000));
        outputs[0].scriptPubKey = hex"76a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac";

        Transaction memory transaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });

        _addPrevTx(
            inputs[0].txId,
            inputs[0].vout,
            5000000000,
            hex"4104283338ffd784c198147f99aed2cc16709c90b1522e3b3637b312a6f9130e0eda7081e373a96d36be319710cd5c134aaffba81ff08650d7de8af332fe4d8cde20ac"
        );
        bytes32 txId = hex"5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2";
        mock.validateTx(transaction, new bytes[](inputs.length));
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 0);
    }

    function test_validateTx_P2PKH() public {
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

        Transaction memory transaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });

        _addPrevTx(inputs[0].txId, inputs[0].vout, 30000, hex"76a9144904d699fbdb22b2b8e240aa31153c26fbe606a088ac");
        bytes32 txId = hex"44f76b52d6b5c9d2e3ebd0a9edb4fa551743cd97d8e8f23171247e64cae12f5b";
        mock.validateTx(transaction, new bytes[](inputs.length));
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 30000);

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

        transaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });

        _addPrevTx(inputs[0].txId, inputs[0].vout, 10000000, hex"76a91406f1b6703d3f56427bfcfd372f952d50d04b64bd88ac");
        _addPrevTx(inputs[1].txId, inputs[1].vout, 9909107, hex"76a91435508d36cd1919a9588a08bcb9db534b266f6c7e88ac");
        _addPrevTx(inputs[2].txId, inputs[2].vout, 9909107, hex"76a914f46e29212bb165a28993b8109bd0472e0345310c88ac");
        _addPrevTx(inputs[3].txId, inputs[3].vout, 9909107, hex"76a9149d56e762a05ffb6dd15da63672b0e8a1309469c088ac");
        _addPrevTx(inputs[4].txId, inputs[4].vout, 19867218, hex"76a914d4944c48a58a161b898bea6144721e77858a1e3288ac");

        mock.validateTx(transaction, new bytes[](inputs.length));
        txId = hex"a6a0c1bd11c35039b74b1d50e498a1c4f02bd4e8480da35ccf9d0bac2ef7547c";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 80000);
    }

    function test_validateTx_P2SH() public {
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

        Transaction memory transaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });

        _addPrevTx(inputs[0].txId, inputs[0].vout, 36259, hex"a9149678efcda8681c0e1b807b8b094a1f96a87c5bd087");

        bytes[] memory redeemScript = new bytes[](1);
        redeemScript[0] =
            hex"52210330cd0f60c8093b34fcb69d6159be3a942f33560d138d68d277694b0b960f18c52102e3713ed176faff1478aee9ef28147a4b4d99b6ab01612514de9786b388e2d191210314d42df81081b7a871ad950bd0b715cf9ab0f4da576692f18c46701db266636f53ae";
        mock.validateTx(transaction, redeemScript);
        bytes32 txId = hex"c7903b511d301cebae89c8e1eb9a521f742607015044430d5eef2656e88410f2";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 699);

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

        transaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });

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
        mock.validateTx(transaction, redeemScript);
        txId = hex"9d3c6335e0dd47c3fff78649b474936fa001046b61aab8fcfd002750403dc4e3";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 50699);
    }

    function test_validateTx_P2WPKH() public {
        // https://btcscan.org/tx/0601987e3bae4aff6e86313c83df532f1c9c6251a142353da44e2004749f0090
        TxInput[] memory inputs = new TxInput[](2);
        inputs[0].txId = hex"b7823a744abd0aafe6792557bce8254b6c487a80f844181f8b9bdb93c62a3d45";
        inputs[0].vout = bytes4(uint32(0));
        inputs[0].scriptSig = "";
        inputs[0].sequence = 0xffffffff;
        inputs[1].txId = hex"d73e4018e72fcdf3f46ced8e044b970d89e4853ce65f135f11230ddbeda6184b";
        inputs[1].vout = bytes4(uint32(49));
        inputs[1].scriptSig = "";
        inputs[1].sequence = 0xffffffff;

        TxOutput[] memory outputs = new TxOutput[](1);
        outputs[0].amount = bytes8(uint64(781059));
        outputs[0].scriptPubKey = hex"76a914297b00828947f06bbe4015d8d227df0b7bc7de4788ac";

        bytes[][] memory witnesses = new bytes[][](2);
        for (uint256 i; i < witnesses.length; ++i) {
            witnesses[i] = new bytes[](2);
        }
        witnesses[0][0] =
            hex"3045022100868a4576136cb2225bffebd442e20df5e523c8251e2938493ab1f429d86ca5e602206590b80de4bc76008b1b14b9cedeb0c9069956b1703c60d2af78d005850c40ad01";
        witnesses[0][1] = hex"039a3760db95fb87e152c5b82e5d66f55659475ea67c88cdb47fa62c0fde735069";
        witnesses[1][0] =
            hex"3044022057f692f09234de6c48303425d98f47bc4be394314bda5f71a33aa08d056af9b802207d4222293d4590e008079a568cb0e6ad5b56619f3b8e70c0c034465c6bc735b701";
        witnesses[1][1] = hex"036defbddbfe49f2cb2fdc512aae1ee17eaca7b4b3f872ccc0b776a2066d897a05";

        Transaction memory transaction = Transaction({
            isSegwit: true,
            version: 0x00000002,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: witnesses
        });

        _addPrevTx(inputs[0].txId, inputs[0].vout, 516235, hex"00140bfafd6c717cadb22959fb1ed56d37cc71c5f224");
        _addPrevTx(inputs[1].txId, inputs[1].vout, 267708, hex"0014242899d4c7ee551a83e796f7cf37473095ef876b");

        bytes32 txId = hex"0601987e3bae4aff6e86313c83df532f1c9c6251a142353da44e2004749f0090";
        mock.validateTx(transaction, new bytes[](inputs.length));
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 2884);

        // https://btcscan.org/tx/4172c7efdfc9326fdfe4f96b4108ef0fb300ec8b7e17f081666763f3e70d7d38
        inputs = new TxInput[](3);
        inputs[0].txId = hex"7b011fa1ef2ecfbc6009f8979e28e1774deec9f051708cf6d54d5dbff564e9f5";
        inputs[0].vout = bytes4(uint32(1));
        inputs[0].scriptSig = "";
        inputs[0].sequence = 0xfffffffe;
        inputs[1].txId = hex"0001cd7297c1105755fbce1dc4a2a71fcbec16e18c762d0d62097b7558ca7386";
        inputs[1].vout = bytes4(uint32(1));
        inputs[1].scriptSig = "";
        inputs[1].sequence = 0xfffffffc;
        inputs[2].txId = hex"75c5d6cb8f578e4d210e453a5c3ede1b41d48a3e3b04afb2e5e15845be07f39f";
        inputs[2].vout = bytes4(uint32(4));
        inputs[2].scriptSig = "";
        inputs[2].sequence = 0xfffffffb;

        outputs = new TxOutput[](2);
        outputs[0].amount = bytes8(uint64(1340000));
        outputs[0].scriptPubKey = hex"a9149eb8a0684b0884822d89a701d0274b460d42023787";
        outputs[1].amount = bytes8(uint64(1126));
        outputs[1].scriptPubKey = hex"0014d0e05a33dd8023493d212cf670269b0a27302620";

        witnesses = new bytes[][](3);
        for (uint256 i; i < witnesses.length; ++i) {
            witnesses[i] = new bytes[](2);
        }
        witnesses[0][0] =
            hex"3045022100f4d9b484bccdddc79b1975558ac15f5e09a9d4cca8887ec23013bd6f3f7da75f022039482f05bce2593a5e35daa653b167fde6523bfbbdc952fa4765c02a15fa65ac01";
        witnesses[0][1] = hex"037416f88de7ba58cfafd43bb53a7127652e49d1bf7c53a8103a23dba6897e9522";
        witnesses[1][0] =
            hex"3045022100c79f75284fc9645e84353d7a47a8b7c2641b52fbe228614470d6f5864660a0730220102efd7054509414dba42823fd934ed84a670fd9ae1ba2f71a80ad26daa3b9a501";
        witnesses[1][1] = hex"037416f88de7ba58cfafd43bb53a7127652e49d1bf7c53a8103a23dba6897e9522";
        witnesses[2][0] =
            hex"3044022027438091cf06338b79ad3aa9f80b672c45c494646b33e9049ed7a1e33bb24fa902200b111edd4da693d5e45798dd3984b7052098e431eded43628e09a43f6d85f04401";
        witnesses[2][1] = hex"037416f88de7ba58cfafd43bb53a7127652e49d1bf7c53a8103a23dba6897e9522";

        transaction = Transaction({
            isSegwit: true,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: witnesses
        });

        _addPrevTx(inputs[0].txId, inputs[0].vout, 1815, hex"0014d0e05a33dd8023493d212cf670269b0a27302620");
        _addPrevTx(inputs[1].txId, inputs[1].vout, 72503, hex"0014d0e05a33dd8023493d212cf670269b0a27302620");
        _addPrevTx(inputs[2].txId, inputs[2].vout, 1268198, hex"0014d0e05a33dd8023493d212cf670269b0a27302620");

        txId = hex"4172c7efdfc9326fdfe4f96b4108ef0fb300ec8b7e17f081666763f3e70d7d38";
        mock.validateTx(transaction, new bytes[](inputs.length));
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 4274);
    }

    function test_validateTx_P2WSH() public {
        // https://btcscan.org/tx/cab75da6d7fe1531c881d4efdb4826410a2604aa9e6442ab12a08363f34fb408
        TxInput[] memory inputs = new TxInput[](1);
        inputs[0].txId = hex"bd430d52f35166a7dd6251c73a48559ad8b5f41b6c5bc4a6c4c1a3e3702f4287";
        inputs[0].vout = bytes4(uint32(0));
        inputs[0].scriptSig = "";
        inputs[0].sequence = 0xffffffff;

        TxOutput[] memory outputs = new TxOutput[](1);
        outputs[0].amount = bytes8(uint64(73182));
        outputs[0].scriptPubKey = hex"00145d6f02f47dc6c57093df246e3742cfe1e22ab410";

        bytes[][] memory witnesses = new bytes[][](1);
        witnesses[0] = new bytes[](3);
        witnesses[0][0] = "";
        witnesses[0][1] =
            hex"3045022100a9a7b273afe54da5f087cb2d995180251f2950cb3b08cd7126f3ebe0d9323335022008c49c695f8951fbb6837e157b9a243dc8a6c79334af529cde6af20a1749efef01";
        witnesses[0][2] = hex"512103534da516a0ab32f30246620fdfbfaf1921228c1e222c6bd2fcddbcfd9024a1b651ae";

        Transaction memory transaction = Transaction({
            isSegwit: true,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: witnesses
        });

        _addPrevTx(
            inputs[0].txId,
            inputs[0].vout,
            86591,
            hex"0020916ff972855bf7589caf8c46a31f7f33b07d0100d953fde95a8354ac36e98165"
        );

        bytes32 txId = hex"cab75da6d7fe1531c881d4efdb4826410a2604aa9e6442ab12a08363f34fb408";
        mock.validateTx(transaction, new bytes[](inputs.length));
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 13409);

        // https://btcscan.org/tx/c3f8561e3e84d43c051d8b55552491f7c7a5ae7df91557fd41d0a23fd1e7f9d6
        inputs = new TxInput[](1);
        inputs[0].txId = hex"2fff4c03393b3862944cabf856554a3432b776c15a891edec9058fbe814650a9";
        inputs[0].vout = bytes4(uint32(5));
        inputs[0].scriptSig = "";
        inputs[0].sequence = 0xffffffff;

        outputs = new TxOutput[](2);
        outputs[0].amount = bytes8(uint64(9400000));
        outputs[0].scriptPubKey = hex"76a914609c5a63404058e84050589b0d42596df6227f9a88ac";
        outputs[1].amount = bytes8(uint64(2529460));
        outputs[1].scriptPubKey = hex"0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d";

        witnesses = new bytes[][](1);
        witnesses[0] = new bytes[](4);
        witnesses[0][0] = "";
        witnesses[0][1] =
            hex"304402203d4792374190fc43f8a4cc4612c683f5f02ce654d926fb8d342d154965fe4e1a02204afb3b09c6e13582ab05771f7bf6f76ef5fce8b6976c8159e9d0e04561bd40cc01";
        witnesses[0][2] =
            hex"304402206d9cd5e79fac1c3a1f0cdf4591bab7bf24cd7997eef7e580d3c5e08f73c32ee8022053d722c60fcd5ab441a469412b069831a9a633f4ec9c3bdf8419cb53cd4eb69601";
        witnesses[0][3] =
            hex"52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae";

        transaction = Transaction({
            isSegwit: true,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: witnesses
        });

        _addPrevTx(
            inputs[0].txId,
            inputs[0].vout,
            11969460,
            hex"0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
        );

        txId = hex"c3f8561e3e84d43c051d8b55552491f7c7a5ae7df91557fd41d0a23fd1e7f9d6";
        mock.validateTx(transaction, new bytes[](inputs.length));
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 53409);
    }

    function test_validateTx_mixed() public {
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

        Transaction memory transaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });

        _addPrevTx(inputs[0].txId, inputs[0].vout, 98500024, hex"a91462e5205f71ff7146044c73c6ae0f1710bdcf519987");
        _addPrevTx(inputs[1].txId, inputs[1].vout, 8061624, hex"76a914b568d34f957022f79e6f6b6980ddf289b1532ec188ac");

        bytes[] memory redeemScript = new bytes[](2);
        redeemScript[0] =
            hex"522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b612103bc94de59cdfdf34c1b1977570ec1d6cd73532323d6d7cf9ae1418d5c0144ee6652ae";
        redeemScript[1] = "";
        mock.validateTx(transaction, redeemScript);
        bytes32 txId = hex"f228eda842bd635511ae6f4b4b24cc74cc03d385231d10d1d69b15db1442e6db";
        assertEq(mock.getTransaction(txId).serializeTransaction(), transaction.serializeTransaction());
        for (uint256 i; i < transaction.outputs.length; ++i) {
            assertTrue(mock.UTXOs(txId, bytes4(uint32(i))));
        }
        assertEq(mock.collectedFees(), 9908);
    }

    function test_invalid_validateTx() public {
        TxInput[] memory inputs = new TxInput[](0);
        TxOutput[] memory outputs = new TxOutput[](0);
        Transaction memory transaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });
        // no inputs
        vm.expectRevert(Node.InvalidTxInputs.selector);
        mock.validateTx(transaction, new bytes[](1));

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
        mock.validateTx(transaction, data);

        // UTXO is spent
        data = new bytes[](1);
        vm.expectRevert(Node.UTXOisSpent.selector);
        mock.validateTx(transaction, data);

        // not supported script
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"04ffff001d026809");
        vm.expectRevert(Node.NotSupported.selector);
        mock.validateTx(transaction, data);

        // invalid P2PKH script
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"76a914069532d8fec3199b205d1269a3eac85bf55c2fde88ac");
        vm.expectRevert(Script.OP_EqualVerifyFailed.selector);
        mock.validateTx(transaction, data);

        // invalid P2SH script
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"a9149678efcda8681c0e1b807b8b094a1f96a87c5bd087");
        vm.expectRevert(Script.WrongRedeemScriptHash.selector);
        mock.validateTx(transaction, data);

        // invalid output amount
        _addPrevTx(inputs[0].txId, inputs[0].vout, 1, hex"76a914ab4aaa0207f7f87db339fdcec70dc82f257bdb4888ac");
        vm.expectRevert(Node.InvalidFee.selector);
        mock.validateTx(transaction, data);

        // correct tx
        _addPrevTx(inputs[0].txId, inputs[0].vout, 16322340, hex"76a914ab4aaa0207f7f87db339fdcec70dc82f257bdb4888ac");
        mock.validateTx(transaction, data);

        // reusing the same tx
        vm.expectRevert(Node.UTXOisSpent.selector);
        mock.validateTx(transaction, data);
    }

    function test_getTargetAndDifficulty() public {
        (uint256 target, uint256 difficulty) = mock.getTargetAndDifficulty(0);
        assertEq(target, 0x00000000ffff0000000000000000000000000000000000000000000000000000, "Wrong target 0");
        assertEq(difficulty, 1, "Wrong difficulty 0");

        (target, difficulty) = mock.getTargetAndDifficulty(1);
        assertEq(target, 0, "Wrong target 1");
        assertEq(difficulty, 0, "Wrong difficulty 1");

        _addPrevBlock(1, bytes4(0), hex"1715b23e");
        (target, difficulty) = mock.getTargetAndDifficulty(1);
        assertEq(target, 0x00000000000000000015b23e0000000000000000000000000000000000000000, "Wrong target 2");
        assertEq(difficulty, 12973235968799, "Wrong difficulty 2");
    }

    function test_getNewBits() public {
        bytes4 bits = mock.getNewBits(0);
        assertEq(bits, hex"1d00ffff", "Wrong bits 0");

        bits = mock.getNewBits(2000);
        assertEq(bits, bytes4(0), "Wrong bits 1");

        _addPrevBlock(30240, hex"4b2b51b1", hex"1d00ffff");
        _addPrevBlock(32255, hex"4b3aec23", bytes4(0));
        bits = mock.getNewBits(32256);
        assertEq(bits, hex"1d00d86a", "Wrong bits 2");

        _addPrevBlock(895104, hex"681683dd", hex"17025ced");
        _addPrevBlock(897119, hex"68289623", bytes4(0));
        bits = mock.getNewBits(897120);
        assertEq(bits, hex"17025049", "Wrong bits 3");
    }

    function test_getMerkleRoot() public view {
        // https://btcscan.org/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        bytes32[] memory transactionHashes = new bytes32[](1);
        transactionHashes[0] = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b;
        bytes32 merkleRoot = mock.getMerkleRoot(transactionHashes.convertEndian()).convertEndian();
        assertEq(merkleRoot, 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b, "Wrong merkle root 1");

        // https://btcscan.org/block/0000000000005645f58fe9606cca7cadcbfc6f9eabeead130bf8d62acffddd7e
        transactionHashes = new bytes32[](5);
        transactionHashes[0] = 0xf6e9d48ee351dcf586c0ce5ca9b23186c5d0743ac5be18f7e041c8e17b6380bc;
        transactionHashes[1] = 0xc716ad8d5986bc5181f9bc21156d85799e3cb7ab7ada6b92397eccc260b41b5c;
        transactionHashes[2] = 0x7ecb3f8fdddb3a9995322672c9df25b465fa0649a9ad235f6d86095e9bf05c67;
        transactionHashes[3] = 0xc928671cdd46eddddc398592e638728364aaf178d29951482238bf38f801bf20;
        transactionHashes[4] = 0xb08d01eaa28bc3ea8755501520eb40db2e5cb08fd6ac0288b6448aa0e37ac247;
        merkleRoot = mock.getMerkleRoot(transactionHashes.convertEndian()).convertEndian();
        assertEq(merkleRoot, 0x45e939f8032e4791b0da001973821e1b572ce0613cce2291ffddd5d819e8c681, "Wrong merkle root 2");
    }

    function test_findNonce() public view {
        // https://btcscan.org/block/00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
        Block memory blockIn = Block({
            version: 0x00000001,
            timestamp: 0x4966bc61,
            bits: 0x1d00ffff,
            // start early, so we won't run out of gas
            nonce: 0x9962e000,
            prevBlock: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f,
            merkleRoot: 0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098,
            transactionHashes: new bytes32[](1)
        });
        blockIn.transactionHashes[0] = 0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098;
        bytes4 nonce = mock.findNonce(blockIn);
        assertEq(nonce, hex"9962e301", "Wrong nonce");
    }

    function _addPrevTx(bytes32 _txId, bytes4 _vout, uint64 _amount, bytes memory _scriptPubKey) internal {
        mock.addUTXO(_txId, _vout);
        TxOutput[] memory outputs = new TxOutput[](uint32(_vout) + 1);
        outputs[uint32(_vout)].amount = bytes8(_amount);
        outputs[uint32(_vout)].scriptPubKey = _scriptPubKey;
        Transaction memory prevTransaction = Transaction({
            isSegwit: false,
            version: 0x00000001,
            inputs: new TxInput[](0),
            outputs: outputs,
            locktime: 0,
            witness: new bytes[][](0)
        });

        mock.addTransaction(_txId, prevTransaction);
    }

    function _addPrevBlock(uint256 _id, bytes4 _timestamp, bytes4 _bits) internal {
        Block memory prevBlock = Block({
            version: bytes4(0x01000000),
            timestamp: _timestamp,
            bits: _bits,
            nonce: bytes4(0x00000000),
            prevBlock: bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            merkleRoot: bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            transactionHashes: new bytes32[](0)
        });
        mock.addBlock(_id, prevBlock);
    }
}
