// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECBTC} from "../../src/lib/ECBTC.sol";
import {Point} from "../../src/lib/Structs.sol";
import "forge-std/Test.sol";

contract BaseTest is Test {
    using ECBTC for uint256;

    uint256 constant privateKey = uint256(keccak256("Some private key"));
    uint256 constant anotherPrivateKey = uint256(keccak256("Another private key"));
    uint256 constant thirdPrivateKey = uint256(keccak256("Third private key"));
    uint256 constant messageHash = uint256(keccak256("Some message to sign"));
    uint256 constant anotherMessageHash = uint256(keccak256("Another message to sign"));
    Point pubKey = privateKey.mulG();
    Point anotherPubKey = anotherPrivateKey.mulG();
    Point thirdPubKey = thirdPrivateKey.mulG();
}
