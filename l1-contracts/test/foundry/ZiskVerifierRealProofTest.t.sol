// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {IVerifier} from "contracts/state-transition/chain-interfaces/IVerifier.sol";
import {ZiskVerifier} from "contracts/state-transition/verifiers/ZiskVerifier.sol";
import {MultiProofVerifier} from "contracts/state-transition/verifiers/MultiProofVerifier.sol";

/// @dev Mock Airbender verifier that always accepts (the Airbender side is
///      exercised with its own real-proof fixtures elsewhere).
contract MockAirbenderVerifier is IVerifier {
    function verify(uint256[] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verificationKeyHash() external pure returns (bytes32) {
        return bytes32(uint256(1));
    }
}

/// @notice End-to-end verification of a real ZiSK proof on the generated
///         on-chain verifier stack.
/// @dev The fixture is a cargo-zisk v0.18.0 `prove --plonk` output for a real
///      ZKsync OS batch: a 768-byte BN254 PLONK SNARK plus the 320-byte
///      public values `programVK(32) || guest publics(256) || rootCVadcopFinal(32)`.
///      The circuit's single public signal is `sha256(publicValues) % r`.
contract ZiskVerifierRealProofTest is Test {
    /// @dev Real 768-byte ZiSK BN254 PLONK SNARK proof.
    bytes internal constant PROOF =
        hex"216a4ed30f731543fda053b2c4fe5100697757bc825a5ad97168e93382568a01228b7dd8212a37105f78a0c70292588270aa17b9f63ec5a0805689cd577a339201e3f72d50091d89e60985159cc74783b5db8ce30ecb8522af21abddf523f51621dd29bd89c5d987b71aba7f774a74dd45d3291869b242893441c8f7971bb50004af67ab54699b8791cbbd66afa597d243fdb996c1cb97a3492a3d755e80f94f0fdb0b6db84e798c2e5fbbf92e5cf6c8aede475a901562054db6415cc53b1bab21b471a3bf368c0b0875b60ffc63649efb5d5cf757f5cb587c59f1ba05ed536d2abf5252448efc2c887841159d3eea843f4fd631db9f4256d27ac80a8d83c2741f39d7643f8ae7e85c51e64805dbb4b7bad24e5e2866f9429d1d7cff50b200d415b982c5d408856741d0a6ad90c4a3bc0579e105b8642b954f200413cb0680861f8b586b8bf210edf2407a5811844c1657abab2615925dd6deca71b780b1868a1e0d284c5a1d4d912d2fe366c2f234f082d0506fea03ddde39cb08b580a1d42119adfd2e45556b34e5bf76c31e4ae86eca0b2b95172363c426219c7fefa7d8eb0dfaaffc440ef62eae056d3e07d9537914088df9ce48738d591b9292fc3aa7e0107043a27f0a44a09de3a1fcab6c987c853ba1791f2931c2f066571b42ed70f80913219c19cb462f946d67d28696b483e61d4e56217a247ee345ab2023e52305053586b064256dfbe5f0126db9c65ddcfc643faa60fa340032ba6cc991b41f251e6d1a48ba4cf71c52bc6a33b377c6a90e43dfd4275540c1c6fd6407b3fd9f1002b033f1fb026667d14a3a7b18a0b004ac2af0567083ba5a8867829bbb1bb46c0cc4a4a981b2bbac834dfc9c3b17db465ffa5d6ce5df6f776055ec957e68b0932c55545786d23f47c7c82736eda15f8487a59048b0849985984cf3da429d079a2432c44c98c797dd65e35ad91ea9515c05d0ebcd73ed8fa8b978670e572dcb841cd04c0edb0cf5aae6be802d42089832d80da1c8575684924760f7c8ed2196ba25f9bac5859649406df26a7af9b5278f14109628a145ce417f76475b237022b4";

    /// @dev Real 320-byte ZiSK public values.
    bytes internal constant PUBLIC_VALUES =
        hex"8c524538f5d736a2885f95bbf173d23a72712a9929767c44bcedd358adcf1fd8b35685d5f5511ec665bc7918003b3fa0bc156b12b7421791f3cffdc3c1bb622c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";

    /// @dev Batch commitment carried in public-values word 1 (bytes [32..64]).
    bytes32 internal constant BATCH_COMMITMENT =
        0xb35685d5f5511ec665bc7918003b3fa0bc156b12b7421791f3cffdc3c1bb622c;

    ZiskVerifier internal ziskVerifier;
    MultiProofVerifier internal multiProofVerifier;

    function setUp() public {
        ziskVerifier = new ZiskVerifier();
        multiProofVerifier = new MultiProofVerifier(
            IVerifier(address(new MockAirbenderVerifier())),
            IVerifier(address(ziskVerifier)),
            address(this)
        );
    }

    /// @dev Build the 34-word ZiSK section (24 proof words + 10 public-values
    ///      words) exactly as MultiProofVerifier hands it to ZiskVerifier.
    function _ziskSection() internal pure returns (uint256[] memory words) {
        words = new uint256[](34);
        bytes memory proofBytes = PROOF;
        bytes memory publicValues = PUBLIC_VALUES;
        for (uint256 i = 0; i < 24; i++) {
            uint256 w;
            assembly {
                w := mload(add(add(proofBytes, 32), mul(i, 32)))
            }
            words[i] = w;
        }
        for (uint256 i = 0; i < 10; i++) {
            uint256 w;
            assembly {
                w := mload(add(add(publicValues, 32), mul(i, 32)))
            }
            words[24 + i] = w;
        }
    }

    /// @dev The exposed wire-form pins are exactly the fixture's public-values
    ///      bytes [0..32] and [288..320], and the VK hash commits to them.
    function test_pinnedWireForms_exposed() public view {
        bytes memory publicValues = PUBLIC_VALUES;
        bytes32 wireProgramVk;
        bytes32 wireRootC;
        assembly {
            wireProgramVk := mload(add(publicValues, 32))
            wireRootC := mload(add(publicValues, add(32, 288)))
        }

        assertEq(ziskVerifier.programVK(), wireProgramVk);
        assertEq(ziskVerifier.rootCVadcopFinal(), wireRootC);
        assertEq(
            keccak256(abi.encodePacked(ziskVerifier.programVK(), ziskVerifier.rootCVadcopFinal())),
            ziskVerifier.verificationKeyHash()
        );
    }

    function test_realProof_ziskVerifier_accepts() public view {
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = uint256(BATCH_COMMITMENT) >> 32;

        assertTrue(ziskVerifier.verify(publicInputs, _ziskSection()));
    }

    function test_realProof_multiProof_type5_accepts() public view {
        // With previous_hash = 0 and a single public input, the batch public
        // input equals publicInputs[0]; it must be the ZiSK batch commitment
        // truncated by 32 bits.
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = uint256(BATCH_COMMITMENT) >> 32;

        uint256 airbenderLen = 2;
        uint256[] memory ziskSection = _ziskSection();
        uint256[] memory proof = new uint256[](3 + airbenderLen + 34);
        proof[0] = 5; // MULTI_PROOF_TYPE
        proof[1] = 0; // previous_hash
        proof[2] = airbenderLen;
        proof[3] = 111; // placeholder Airbender proof words (mock accepts)
        proof[4] = 222;
        for (uint256 i = 0; i < 34; i++) {
            proof[5 + i] = ziskSection[i];
        }

        assertTrue(multiProofVerifier.verify(publicInputs, proof));
    }

    function test_realProof_tamperedPublics_rejected() public view {
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = uint256(BATCH_COMMITMENT) >> 32;

        // Flip one bit of the batch commitment: the digest changes and the
        // pairing check must fail.
        uint256[] memory words = _ziskSection();
        words[25] ^= 1;

        assertFalse(ziskVerifier.verify(publicInputs, words));
    }

    function test_realProof_wrongProgramVk_rejected() public view {
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = uint256(BATCH_COMMITMENT) >> 32;

        // A proof for a different guest ELF (different programVK) is refused
        // before any pairing work.
        uint256[] memory words = _ziskSection();
        words[24] ^= 1;

        assertFalse(ziskVerifier.verify(publicInputs, words));
    }

    function test_realProof_wrongVadcopVk_rejected() public view {
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = uint256(BATCH_COMMITMENT) >> 32;

        // A proof from a different SNARK circuit generation (different
        // rootCVadcopFinal) is refused before any pairing work.
        uint256[] memory words = _ziskSection();
        words[33] ^= 1;

        assertFalse(ziskVerifier.verify(publicInputs, words));
    }

    function test_realProof_tamperedSnark_rejected() public view {
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = uint256(BATCH_COMMITMENT) >> 32;

        // Corrupt a proof scalar (an opening evaluation, so it stays a valid
        // field element): the pairing check must fail.
        uint256[] memory words = _ziskSection();
        words[23] ^= 1;

        assertFalse(ziskVerifier.verify(publicInputs, words));
    }

    function test_realProof_multiProof_wrongBatchInput_rejected() public {
        // The Airbender side (mocked to accept) claims a DIFFERENT batch than
        // the ZiSK public values commit to: the cross-proof binding must revert.
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = (uint256(BATCH_COMMITMENT) >> 32) ^ 1;

        uint256 airbenderLen = 2;
        uint256[] memory ziskSection = _ziskSection();
        uint256[] memory proof = new uint256[](3 + airbenderLen + 34);
        proof[0] = 5;
        proof[1] = 0;
        proof[2] = airbenderLen;
        for (uint256 i = 0; i < 34; i++) {
            proof[5 + i] = ziskSection[i];
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                MultiProofVerifier.ZiskCommitmentMismatch.selector,
                publicInputs[0],
                uint256(BATCH_COMMITMENT) >> 32
            )
        );
        multiProofVerifier.verify(publicInputs, proof);
    }
}
