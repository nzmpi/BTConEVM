// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./utils/BaseTest.sol";
import {SigLib, Signature} from "../src/lib/SigLib.sol";

contract TestSigLib is BaseTest {
    using ECBTC for uint256;
    using SigLib for uint256;

    function test_sign() public {
        Signature memory sig1 = messageHash.sign(privateKey);
        assertNotEq(sig1.r, 0, "Signature1 r should be non-zero");
        assertNotEq(sig1.s, 0, "Signature1 s should be non-zero");

        Signature memory sig2 = messageHash.sign(privateKey);
        assertEq(sig1.r, sig2.r, "Signature2 r should be the same");
        assertEq(sig1.s, sig2.s, "Signature2 s should be the same");

        Signature memory sig3 = anotherMessageHash.sign(privateKey);
        assertNotEq(sig1.r, sig3.r, "Signature3 r should be different");
        assertNotEq(sig1.s, sig3.s, "Signature3 s should be different");

        Signature memory sig4 = messageHash.sign(anotherPrivateKey);
        assertNotEq(sig1.r, sig4.r, "Signature4 r should be different");
        assertNotEq(sig1.s, sig4.s, "Signature4 s should be different");

        // change k by changing block.timestamp
        vm.warp(42);
        Signature memory sig5 = messageHash.sign(privateKey);
        assertNotEq(sig1.r, sig5.r, "Signature5 r should be different");
        assertNotEq(sig1.s, sig5.s, "Signature5 s should be different");
    }

    function test_verify() public view {
        Signature memory sig1 = messageHash.sign(privateKey);
        assertTrue(messageHash.verify(sig1, pubKey), "Signature should be valid");

        Signature memory sig2 = anotherMessageHash.sign(anotherPrivateKey);
        assertTrue(anotherMessageHash.verify(sig2, anotherPubKey), "Another signature should be valid");

        Signature memory sig3 = messageHash.sign(anotherPrivateKey);
        assertTrue(messageHash.verify(sig3, anotherPubKey), "Third signature should be valid");
    }

    function test_invalid_verify() public view {
        Signature memory sig = messageHash.sign(privateKey);

        // Wrong message hash
        assertFalse(anotherMessageHash.verify(sig, pubKey), "Message hash should be invalid");

        // Wrong public key
        assertFalse(messageHash.verify(sig, anotherPubKey), "Public key should be invalid");

        // Wrong signature
        sig.s = sig.s.add(1);
        assertFalse(messageHash.verify(sig, pubKey), "Signature should be invalid");
    }
}
