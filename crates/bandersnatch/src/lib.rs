// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! VRFs backed by [Bandersnatch](https://neuromancer.sk/std/bls/Bandersnatch),
//! an elliptic curve built over BLS12-381 scalar field.
//!
//! The primitive can operate both as a regular VRF or as an anonymized Ring VRF.

extern crate bandersnatch_vrfs;
extern crate codec;
extern crate core;

use core::mem;
use std::{ptr, slice};

use bandersnatch_vrfs::{CanonicalSerialize, SecretKey};
use codec::Decode;

/// Context used to produce a plain signature without any VRF input/output.
const SIGNING_CTX: &[u8] = b"BandersnatchSigningContext";

const SEED_SERIALIZED_SIZE: usize = 32;

const PUBLIC_SERIALIZED_SIZE: usize = 33;
const SIGNATURE_SERIALIZED_SIZE: usize = 65;
const PREOUT_SERIALIZED_SIZE: usize = 33;

/// Max number of inputs/outputs which can be handled by the VRF signing procedures.
///
/// The number is quite arbitrary and chosen to fulfill the use cases found so far.
/// If required it can be extended in the future.
// const MAX_VRF_IOS: u32 = 3;

/// Bandersnatch public key.
pub struct Public(pub [u8; PUBLIC_SERIALIZED_SIZE]);

impl Public {
    fn unchecked_from(raw: [u8; PUBLIC_SERIALIZED_SIZE]) -> Self {
        Public(raw)
    }
}

/// Bandersnatch signature.
///
/// The signature is created via the [`VrfSecret::vrf_sign`] using [`SIGNING_CTX`] as transcript `label`.
#[cfg_attr(feature = "full_crypto", derive(Hash))]
#[derive(Clone, Copy, Encode, Decode)]
pub struct Signature([u8; SIGNATURE_SERIALIZED_SIZE]);

/// The raw secret seed, which can be used to reconstruct the secret [`Pair`].
type Seed = [u8; SEED_SERIALIZED_SIZE];

pub trait VrfCrypto {
    /// VRF input.
    type VrfInput;
    /// VRF output.
    type VrfOutput;
    /// VRF signing data.
    type VrfSignData;
    /// VRF signature.
    type VrfSignature;
}

/// VRF Secret Key.
trait VrfSecret: VrfCrypto {
    /// Get VRF-specific output .
    fn vrf_output(&self, data: &Self::VrfInput) -> Self::VrfOutput;

    /// Sign VRF-specific data.
    fn vrf_sign(&self, input: &Self::VrfSignData) -> Self::VrfSignature;
}

/// VRF Public Key.
trait VrfPublic: VrfCrypto {
    /// Verify input data signature.
    fn vrf_verify(&self, data: &Self::VrfSignData, signature: &Self::VrfSignature) -> bool;
}

/// Bandersnatch secret key.
#[derive(Clone)]
struct Pair {
    secret: SecretKey,
    _seed: Seed,
}

impl Pair {
    //     type Seed = Seed;
    //     type Public = Public;
    //     type Signature = Signature;
    //
    //     /// Make a new key pair from secret seed material.
    //     ///
    //     /// The slice must be 32 bytes long or it will return an error.
    //     fn from_seed_slice(seed_slice: &[u8]) -> Result<Pair, SecretStringError> {
    //         if seed_slice.len() != SEED_SERIALIZED_SIZE {
    //             return Err(SecretStringError::InvalidSeedLength);
    //         }
    //         let mut seed = [0; SEED_SERIALIZED_SIZE];
    //         seed.copy_from_slice(seed_slice);
    //         let secret = SecretKey::from_seed(&seed);
    //         Ok(Pair { secret, seed })
    //     }
    //
    //     /// Derive a child key from a series of given (hard) junctions.
    //     ///
    //     /// Soft junctions are not supported.
    //     fn derive<Iter: Iterator<Item = DeriveJunction>>(
    //         &self,
    //         path: Iter,
    //         _seed: Option<Seed>,
    //     ) -> Result<(Pair, Option<Seed>), DeriveError> {
    //         let derive_hard = |seed, cc| -> Seed {
    //             ("bandersnatch-vrf-HDKD", seed, cc).using_encoded(sp_core_hashing::blake2_256)
    //         };
    //
    //         let mut seed = self.seed();
    //         for p in path {
    //             if let DeriveJunction::Hard(cc) = p {
    //                 seed = derive_hard(seed, cc);
    //             } else {
    //                 return Err(DeriveError::SoftKeyInPath);
    //             }
    //         }
    //         Ok((Self::from_seed(&seed), Some(seed)))
    //     }
    //
    //     fn public(&self) -> Public {
    //         let public = self.secret.to_public();
    //         let mut raw = [0; PUBLIC_SERIALIZED_SIZE];
    //         public
    //             .serialize_compressed(raw.as_mut_slice())
    //             .expect("serialization length is constant and checked by test; qed");
    //         Public::unchecked_from(raw)
    //     }

    /// Sign a message.
    ///
    /// In practice this produce a Schnorr signature of a transcript composed by
    /// the constant label [`SIGNING_CTX`] and `data` without any additional data.
    ///
    /// See [`vrf::VrfSignData`] for additional details.
    fn sign(&self, data: &[u8]) -> Signature {
        let data = vrf::VrfSignData::new_unchecked(SIGNING_CTX, &[data], None);
        self.vrf_sign(&data).signature
    }

    fn verify<M: AsRef<[u8]>>(signature: &Signature, data: M, public: &Public) -> bool {
        let data = vrf::VrfSignData::new_unchecked(SIGNING_CTX, &[data.as_ref()], None);
        let signature = vrf::VrfSignature {
            signature: *signature,
            outputs: vrf::VrfIosVec::default(),
        };
        public.vrf_verify(&data, &signature)
    }
}

/// Bandersnatch VRF types and operations.
mod vrf {
    use bandersnatch_vrfs::{
        CanonicalDeserialize,
        CanonicalSerialize,
        IntoVrfInput,
        Message,
        ThinVrfSignature,
        Transcript,
    };
    use codec::EncodeLike;
    use crate::Decode;
    use crate::Encode;
    use crate::Pair;
    use crate::Public;
    use crate::PublicKey;
    use crate::Signature;
    use crate::VrfCrypto;
    use crate::VrfPublic;
    use crate::VrfSecret;
    use crate::PREOUT_SERIALIZED_SIZE;
    use crate::SIGNATURE_SERIALIZED_SIZE;

    /// Bounded vector used for VRF inputs and outputs.
    ///
    /// Can contain at most [`MAX_VRF_IOS`] elements.
    pub type VrfIosVec<T> = Vec<T>; //BoundedVec<T, ConstU32<MAX_VRF_IOS>>;

    /// VRF input to construct a [`VrfOutput`] instance and embeddable in [`VrfSignData`].
    #[derive(Clone, Debug)]
    pub struct VrfInput(pub(super) bandersnatch_vrfs::VrfInput);

    impl VrfInput {
        /// Construct a new VRF input.
        pub fn new(domain: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Self {
            let msg = Message {
                domain: domain.as_ref(),
                message: data.as_ref(),
            };
            VrfInput(msg.into_vrf_input())
        }
    }

    /// VRF (pre)output derived from [`VrfInput`] using a [`VrfSecret`].
    ///
    /// This object is used to produce an arbitrary number of verifiable pseudo random
    /// bytes and is often called pre-output to emphasize that this is not the actual
    /// output of the VRF but an object capable of generating the output.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct VrfOutput(pub(super) bandersnatch_vrfs::VrfPreOut);

    impl Encode for VrfOutput {
        fn encode(&self) -> Vec<u8> {
            let mut bytes = [0; PREOUT_SERIALIZED_SIZE];
            self.0
                .serialize_compressed(bytes.as_mut_slice())
                .expect("serialization length is constant and checked by test; qed");
            bytes.encode()
        }
    }

    impl Decode for VrfOutput {
        fn decode<R: codec::Input>(i: &mut R) -> Result<Self, codec::Error> {
            let buf = <[u8; PREOUT_SERIALIZED_SIZE]>::decode(i)?;
            let preout =
                bandersnatch_vrfs::VrfPreOut::deserialize_compressed_unchecked(buf.as_slice())
                    .map_err(|_| "vrf-preout decode error: bad preout")?;
            Ok(VrfOutput(preout))
        }
    }

    impl EncodeLike for VrfOutput {}

    /// Data to be signed via one of the two provided vrf flavors.
    ///
    /// The object contains a transcript and a sequence of [`VrfInput`]s ready to be signed.
    ///
    /// The `transcript` summarizes a set of messages which are defining a particular
    /// protocol by automating the Fiat-Shamir transform for challenge generation.
    /// A good explaination of the topic can be found in Merlin [docs](https://merlin.cool/)
    ///
    /// The `inputs` is a sequence of [`VrfInput`]s which, during the signing procedure, are
    /// first transformed to [`VrfOutput`]s. Both inputs and outputs are then appended to
    /// the transcript before signing the Fiat-Shamir transform result (the challenge).
    ///
    /// In practice, as a user, all these technical details can be easily ignored.
    /// What is important to remember is:
    /// - *Transcript* is an object defining the protocol and used to produce the signature. This
    ///   object doesn't influence the `VrfOutput`s values.
    /// - *Vrf inputs* is some additional data which is used to produce *vrf outputs*. This data
    ///   will contribute to the signature as well.
    #[derive(Clone)]
    pub struct VrfSignData {
        /// Associated protocol transcript.
        pub transcript: Transcript,
        /// VRF inputs to be signed.
        pub inputs: VrfIosVec<VrfInput>,
    }

    impl VrfSignData {
        /// Construct a new data to be signed.
        ///
        /// At most the first [`MAX_VRF_IOS`] elements of `inputs` are used.
        ///
        /// Refer to [`VrfSignData`] for details about transcript and inputs.
        pub fn new_unchecked(
            transcript_label: &'static [u8],
            transcript_data: impl IntoIterator<Item = impl AsRef<[u8]>>,
            inputs: impl IntoIterator<Item = VrfInput>,
        ) -> Self {
            let inputs: Vec<VrfInput> = inputs.into_iter().collect();
            //let inputs = VrfIosVec::truncate_from(inputs);
            let mut transcript = Transcript::new_labeled(transcript_label);
            transcript_data
                .into_iter()
                .for_each(|data| transcript.append(data.as_ref()));
            VrfSignData { transcript, inputs }
        }

        // /// Append a message to the transcript.
        // pub fn push_transcript_data(&mut self, data: &[u8]) {
        //     self.transcript.append(data);
        // }
        //
        // /// Tries to append a [`VrfInput`] to the vrf inputs list.
        // ///
        // /// On failure, returns back the [`VrfInput`] parameter.
        // pub fn push_vrf_input(&mut self, input: VrfInput) -> Result<(), VrfInput> {
        //     self.inputs.try_push(input)
        // }

        /// Get the challenge associated to the `transcript` contained within the signing data.
        ///
        /// Ignores the vrf inputs and outputs.
        pub fn challenge<const N: usize>(&self) -> [u8; N] {
            let mut output = [0; N];
            let mut transcript = self.transcript.clone();
            let mut reader = transcript.challenge(b"bandersnatch challenge");
            reader.read_bytes(&mut output);
            output
        }
    }

    /// VRF signature.
    ///
    /// Includes both the transcript `signature` and the `outputs` generated from the
    /// [`VrfSignData::inputs`].
    ///
    /// Refer to [`VrfSignData`] for more details.
    #[derive(Encode, Decode /*, MaxEncodedLen*/)]
    pub struct VrfSignature {
        /// VRF (pre)outputs.
        pub outputs: VrfIosVec<VrfOutput>,
        /// Transcript signature.
        pub signature: Signature,
    }

        impl VrfCrypto for Pair {
        type VrfInput = VrfInput;
        type VrfOutput = VrfOutput;
        type VrfSignData = VrfSignData;
        type VrfSignature = VrfSignature;
    }

        impl VrfSecret for Pair {
        fn vrf_sign(&self, data: &Self::VrfSignData) -> Self::VrfSignature {
            // const _: () = assert!(MAX_VRF_IOS == 3, "`MAX_VRF_IOS` expected to be 3");
            // Workaround to overcome backend signature generic over the number of IOs.
            match data.inputs.len() {
                0 => self.vrf_sign_gen::<0>(data),
                1 => self.vrf_sign_gen::<1>(data),
                2 => self.vrf_sign_gen::<2>(data),
                3 => self.vrf_sign_gen::<3>(data),
                _ => unreachable!(),
            }
        }

        fn vrf_output(&self, input: &Self::VrfInput) -> Self::VrfOutput {
            let output = self.secret.vrf_preout(&input.0);
            VrfOutput(output)
        }
    }

    impl VrfCrypto for Public {
        type VrfInput = VrfInput;
        type VrfOutput = VrfOutput;
        type VrfSignData = VrfSignData;
        type VrfSignature = VrfSignature;
    }

    impl VrfPublic for Public {
        fn vrf_verify(&self, data: &Self::VrfSignData, signature: &Self::VrfSignature) -> bool {
            // const _: () = assert!(MAX_VRF_IOS == 3, "`MAX_VRF_IOS` expected to be 3");
            let outputs_len = signature.outputs.len();
            if outputs_len != data.inputs.len() {
                return false;
            }
            // Workaround to overcome backend signature generic over the number of IOs.
            match outputs_len {
                0 => self.vrf_verify_gen::<0>(data, signature),
                1 => self.vrf_verify_gen::<1>(data, signature),
                2 => self.vrf_verify_gen::<2>(data, signature),
                3 => self.vrf_verify_gen::<3>(data, signature),
                _ => unreachable!(),
            }
        }
    }

        impl Pair {
        fn vrf_sign_gen<const N: usize>(&self, data: &VrfSignData) -> VrfSignature {
            let ios = core::array::from_fn(|i| self.secret.vrf_inout(data.inputs[i].0));

            let thin_signature: ThinVrfSignature<N> =
                self.secret.sign_thin_vrf(data.transcript.clone(), &ios);

            let outputs: Vec<_> = thin_signature
                .preouts
                .iter()
                .map(|f| VrfOutput(f.clone()))
                .collect();
            //let outputs = VrfIosVec::truncate_from(outputs);

            let mut signature = VrfSignature {
                signature: Signature([0; SIGNATURE_SERIALIZED_SIZE]),
                outputs,
            };

            thin_signature
                .proof
                .serialize_compressed(signature.signature.0.as_mut_slice())
                .expect("serialization length is constant and checked by test; qed");

            signature
        }
    }

    impl Public {
        fn vrf_verify_gen<const N: usize>(
            &self,
            data: &VrfSignData,
            signature: &VrfSignature,
        ) -> bool {
            let Ok(public) = PublicKey::deserialize_compressed_unchecked(self.0.as_slice()) else {
                return false;
            };

            let preouts: [bandersnatch_vrfs::VrfPreOut; N] =
                core::array::from_fn(|i| signature.outputs[i].0);

            // Deserialize only the proof, the rest has already been deserialized
            // This is another hack used because backend signature type is generic over
            // the number of ios.
            let Ok(proof) =
                ThinVrfSignature::<0>::deserialize_compressed_unchecked(&signature.signature.0[..])
                    .map(|s| s.proof)
            else {
                return false;
            };
            let signature = ThinVrfSignature { proof, preouts };

            let inputs = data.inputs.iter().map(|i| i.0);

            public
                .verify_thin_vrf(data.transcript.clone(), inputs, &signature)
                .is_ok()
        }
    }

    impl VrfOutput {
        /// Generate an arbitrary number of bytes from the given `context` and VRF `input`.
        pub fn make_bytes<const N: usize>(
            &self,
            context: &'static [u8],
            input: &VrfInput,
        ) -> [u8; N] {
            let transcript = Transcript::new_labeled(context);
            let inout = bandersnatch_vrfs::VrfInOut {
                input: input.0,
                preoutput: self.0,
            };
            inout.vrf_output_bytes(transcript)
        }
    }
}

/// Bandersnatch Ring-VRF types and operations.
mod ring_vrf {
    use super::{vrf::*, *};

    pub use bandersnatch_vrfs::ring::{
        // RingProof,
        RingProver,
        RingVerifier,
        KZG,
    };
    use bandersnatch_vrfs::CanonicalDeserialize;

    /// Overhead in the domain size with respect to the supported ring size.
    ///
    /// Some bits of the domain are reserved for the zk-proof to work.
    // const RING_DOMAIN_OVERHEAD: u32 = 257;

    // Max size of serialized ring-vrf context given `domain_len`.
    pub(crate) const fn ring_context_serialized_size(domain_len: u32) -> usize {
        // const G1_POINT_COMPRESSED_SIZE: usize = 48;
        // const G2_POINT_COMPRESSED_SIZE: usize = 96;
        const G1_POINT_UNCOMPRESSED_SIZE: usize = 96;
        const G2_POINT_UNCOMPRESSED_SIZE: usize = 192;
        const OVERHEAD_SIZE: usize = 20;
        const G2_POINTS_NUM: usize = 2;
        let g1_points_num = 3 * domain_len as usize + 1;

        OVERHEAD_SIZE
            + g1_points_num * G1_POINT_UNCOMPRESSED_SIZE
            + G2_POINTS_NUM * G2_POINT_UNCOMPRESSED_SIZE
    }

    //     pub(crate) const RING_VERIFIER_DATA_SERIALIZED_SIZE: usize = 388;
    pub(crate) const RING_SIGNATURE_SERIALIZED_SIZE: usize = 755;

    //     /// remove as soon as soon as serialization is implemented by the backend
    //     pub struct RingVerifierData {
    //         /// Domain size.
    //         pub domain_size: u32,
    //         /// Verifier key.
    //         pub verifier_key: VerifierKey,
    //     }
    //
    //     impl From<RingVerifierData> for RingVerifier {
    //         fn from(vd: RingVerifierData) -> RingVerifier {
    //             bandersnatch_vrfs::ring::make_ring_verifier(vd.verifier_key, vd.domain_size as usize)
    //         }
    //     }
    //
    //     impl Encode for RingVerifierData {
    //         fn encode(&self) -> Vec<u8> {
    //             const ERR_STR: &str = "serialization length is constant and checked by test; qed";
    //             let mut buf = [0; RING_VERIFIER_DATA_SERIALIZED_SIZE];
    //             self.domain_size
    //                 .serialize_compressed(&mut buf[..4])
    //                 .expect(ERR_STR);
    //             self.verifier_key
    //                 .serialize_compressed(&mut buf[4..])
    //                 .expect(ERR_STR);
    //             buf.encode()
    //         }
    //     }
    //
    //     impl Decode for RingVerifierData {
    //         fn decode<R: codec::Input>(i: &mut R) -> Result<Self, codec::Error> {
    //             const ERR_STR: &str = "serialization length is constant and checked by test; qed";
    //             let buf = <[u8; RING_VERIFIER_DATA_SERIALIZED_SIZE]>::decode(i)?;
    //             let domain_size =
    //                 <u32 as CanonicalDeserialize>::deserialize_compressed_unchecked(&mut &buf[..4])
    //                     .expect(ERR_STR);
    //             let verifier_key = <bandersnatch_vrfs::ring::VerifierKey as CanonicalDeserialize>::deserialize_compressed_unchecked(&mut &buf[4..]).expect(ERR_STR);
    //
    //             Ok(RingVerifierData {
    //                 domain_size,
    //                 verifier_key,
    //             })
    //         }
    //     }
    //
    //     impl EncodeLike for RingVerifierData {}
    //
    //     impl MaxEncodedLen for RingVerifierData {
    //         fn max_encoded_len() -> usize {
    //             <[u8; RING_VERIFIER_DATA_SERIALIZED_SIZE]>::max_encoded_len()
    //         }
    //     }
    //
    //     impl TypeInfo for RingVerifierData {
    //         type Identity = [u8; RING_VERIFIER_DATA_SERIALIZED_SIZE];
    //
    //         fn type_info() -> scale_info::Type {
    //             Self::Identity::type_info()
    //         }
    //     }

    /// Context used to construct ring prover and verifier.
    ///
    /// Generic parameter `D` represents the ring domain size and drives
    /// the max number of supported ring members [`RingContext::max_keyset_size`]
    /// which is equal to `D - RING_DOMAIN_OVERHEAD`.
    #[derive(Clone)]
    pub struct RingContext<const D: u32>(KZG);

    impl<const D: u32> RingContext<D> {
        /// Get ring prover for the key at index `public_idx` in the `public_keys` set.
        pub fn prover(&self, public_keys: &[Public], public_idx: usize) -> Option<RingProver> {
            let mut pks = Vec::with_capacity(public_keys.len());
            for public_key in public_keys {
                let pk =
                    PublicKey::deserialize_compressed_unchecked(public_key.0.as_slice()).ok()?;
                pks.push(pk.0.into());
            }

            let prover_key = self.0.prover_key(pks);
            let ring_prover = self.0.init_ring_prover(prover_key, public_idx);
            Some(ring_prover)
        }

        /// Get ring verifier for the `public_keys` set.
        pub fn verifier(&self, public_keys: &[Public]) -> Option<RingVerifier> {
            let mut pks = Vec::with_capacity(public_keys.len());
            for public_key in public_keys {
                let pk =
                    PublicKey::deserialize_compressed_unchecked(public_key.0.as_slice()).ok()?;
                pks.push(pk.0.into());
            }

            let verifier_key = self.0.verifier_key(pks);
            let ring_verifier = self.0.init_ring_verifier(verifier_key);
            Some(ring_verifier)
        }

        // /// Information required for a lazy construction of a ring verifier.
        // pub fn verifier_data(&self, public_keys: &[Public]) -> Option<RingVerifierData> {
        //     let mut pks = Vec::with_capacity(public_keys.len());
        //     for public_key in public_keys {
        //         let pk = PublicKey::deserialize_compressed_unchecked(public_key.as_slice()).ok()?;
        //         pks.push(pk.0.into());
        //     }
        //     Some(RingVerifierData {
        //         verifier_key: self.0.verifier_key(pks),
        //         domain_size: self.0.domain_size,
        //     })
        // }
    }

    // impl<const D: u32> Encode for RingContext<D> {
    //     fn encode(&self) -> Vec<u8> {
    //         let mut buf = vec![0; ring_context_serialized_size(D)];
    //         self.0
    //             .serialize_uncompressed(buf.as_mut_slice())
    //             .expect("serialization length is constant and checked by test; qed");
    //         buf
    //     }
    // }

    impl<const D: u32> Decode for RingContext<D> {
        fn decode<R: codec::Input>(input: &mut R) -> Result<Self, codec::Error> {
            let mut buf = vec![0; ring_context_serialized_size(D)];
            input.read(&mut buf[..])?;
            let kzg = KZG::deserialize_uncompressed_unchecked(buf.as_slice())
                .map_err(|_| "KZG decode error")?;
            Ok(RingContext(kzg))
        }
    }

    /// Ring VRF signature.
    #[derive(Encode, Decode)]
    pub struct RingVrfSignature {
        /// VRF (pre)outputs.
        pub outputs: VrfIosVec<VrfOutput>,
        /// Ring signature.
        pub signature: [u8; RING_SIGNATURE_SERIALIZED_SIZE],
    }

        impl Pair {
        /// Produce a ring-vrf signature.
        ///
        /// The ring signature is verifiable if the public key corresponding to the
        /// signing [`Pair`] is part of the ring from which the [`RingProver`] has
        /// been constructed. If not, the produced signature is just useless.
        pub fn ring_vrf_sign(&self, data: &VrfSignData, prover: &RingProver) -> RingVrfSignature {
            // const _: () = assert!(MAX_VRF_IOS == 3, "`MAX_VRF_IOS` expected to be 3");
            // Workaround to overcome backend signature generic over the number of IOs.
            match data.inputs.len() {
                0 => self.ring_vrf_sign_gen::<0>(data, prover),
                1 => self.ring_vrf_sign_gen::<1>(data, prover),
                2 => self.ring_vrf_sign_gen::<2>(data, prover),
                3 => self.ring_vrf_sign_gen::<3>(data, prover),
                _ => unreachable!(),
            }
        }

        fn ring_vrf_sign_gen<const N: usize>(
            &self,
            data: &VrfSignData,
            prover: &RingProver,
        ) -> RingVrfSignature {
            let ios = core::array::from_fn(|i| self.secret.vrf_inout(data.inputs[i].0));

            let ring_signature: bandersnatch_vrfs::RingVrfSignature<N> =
                bandersnatch_vrfs::RingProver {
                    ring_prover: prover,
                    secret: &self.secret,
                }
                .sign_ring_vrf(data.transcript.clone(), &ios);

            let outputs: Vec<_> = ring_signature
                .preouts
                .iter()
                .map(|f| VrfOutput(f.clone()))
                .collect();
            // let outputs = VrfIosVec::truncate_from(outputs);

            let mut signature = RingVrfSignature {
                outputs,
                signature: [0; RING_SIGNATURE_SERIALIZED_SIZE],
            };

            ring_signature
                .proof
                .serialize_compressed(signature.signature.as_mut_slice())
                .expect("serialization length is constant and checked by test; qed");

            signature
        }
    }

    impl RingVrfSignature {
        /// Verify a ring-vrf signature.
        ///
        /// The signature is verifiable if it has been produced by a member of the ring
        /// from which the [`RingVerifier`] has been constructed.
        pub fn ring_vrf_verify(&self, data: &VrfSignData, verifier: &RingVerifier) -> bool {
            // const _: () = assert!(MAX_VRF_IOS == 3, "`MAX_VRF_IOS` expected to be 3");
            let preouts_len = self.outputs.len();
            if preouts_len != data.inputs.len() {
                return false;
            }
            // Workaround to overcome backend signature generic over the number of IOs.
            match preouts_len {
                0 => self.ring_vrf_verify_gen::<0>(data, verifier),
                1 => self.ring_vrf_verify_gen::<1>(data, verifier),
                2 => self.ring_vrf_verify_gen::<2>(data, verifier),
                3 => self.ring_vrf_verify_gen::<3>(data, verifier),
                _ => unreachable!(),
            }
        }

        fn ring_vrf_verify_gen<const N: usize>(
            &self,
            data: &VrfSignData,
            verifier: &RingVerifier,
        ) -> bool {
            let Ok(vrf_signature) =
                bandersnatch_vrfs::RingVrfSignature::<0>::deserialize_compressed_unchecked(
                    self.signature.as_slice(),
                )
            else {
                return false;
            };

            let preouts: [bandersnatch_vrfs::VrfPreOut; N] =
                core::array::from_fn(|i| self.outputs[i].0);

            let signature = bandersnatch_vrfs::RingVrfSignature {
                proof: vrf_signature.proof,
                preouts,
            };

            let inputs = data.inputs.iter().map(|i| i.0);

            bandersnatch_vrfs::RingVerifier(verifier)
                .verify_ring_vrf(data.transcript.clone(), inputs, &signature)
                .is_ok()
        }
    }
}

pub const BANDERSNATCH_SEED_SIZE: usize = 32; // SEED_SERIALIZED_SIZE
pub const BANDERSNATCH_SECRET_KEY_SIZE: usize = BANDERSNATCH_SEED_SIZE;
pub const BANDERSNATCH_PUBLIC_KEY_SIZE: usize = 33; // PUBLIC_KEY_LENGTH
pub const BANDERSNATCH_SIGNATURE_SIZE: usize = 65; // SIGNATURE_SERIALIZED_SIZE
pub const BANDERSNATCH_RING_SIGNATURE_SIZE: usize = 755; //RING_SIGNATURE_SERIALIZED_SIZE
pub const BANDERSNATCH_PREOUT_SIZE: usize = 33; //PREOUT_SERIALIZED_SIZE

//use bandersnatch_vrfs::bandersnatch::SWAffine;
use bandersnatch_vrfs::ring::{RingProver, RingVerifier};
use bandersnatch_vrfs::scale::Encode;
//use bandersnatch_vrfs::vrf::VrfPreOut;
use bandersnatch_vrfs::PublicKey;
//use ptr::copy;
// use ring_vrf::RingContext;
// use ring_vrf::{RingVrfSignature, RING_SIGNATURE_SERIALIZED_SIZE};
use ring_vrf::RingVrfSignature;
// use slice::from_raw_parts;
// use slice::from_raw_parts_mut;
use std::ptr::null;
use vrf::{VrfInput, VrfOutput, VrfSignData};

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_keypair_from_seed(seed_ptr: *const u8, keypair_out: *mut u8) {
    let seed = *(seed_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);

    let secret = SecretKey::from_seed(&seed);
    let public = secret.to_public();

    // Fake secret key
    ptr::copy(
        [0; BANDERSNATCH_SECRET_KEY_SIZE].as_ptr(),
        keypair_out,
        BANDERSNATCH_SECRET_KEY_SIZE as usize,
    );

    // Fake secret key
    ptr::copy(seed_ptr, keypair_out, BANDERSNATCH_SECRET_KEY_SIZE as usize);

    let x = slice::from_raw_parts_mut(
        keypair_out.wrapping_add(BANDERSNATCH_SECRET_KEY_SIZE),
        BANDERSNATCH_PUBLIC_KEY_SIZE as usize,
    );

    let _ = public.serialize(x);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_sign(
    secret_ptr: *const u8,
    message_ptr: *const u8,
    message_size: usize,
    signature_out: *mut u8,
) {
    let seed = *(secret_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);

    let secret = SecretKey::from_seed(&seed);

    let data = slice::from_raw_parts(message_ptr, message_size as usize);

    let pair = Pair { secret, _seed: seed };

    let signature = pair.sign(&data);

    ptr::copy(
        signature.0.as_ptr(),
        signature_out,
        BANDERSNATCH_SIGNATURE_SIZE as usize,
    );
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_verify(
    signature_ptr: *const u8,
    message_ptr: *const u8,
    message_size: usize,
    public_ptr: *const u8,
) -> bool {
    let signature = *(signature_ptr as *const [u8; BANDERSNATCH_SIGNATURE_SIZE]);
    let signature = Signature(signature);

    let message = slice::from_raw_parts(message_ptr, message_size);

    let public = *(public_ptr as *const [u8; BANDERSNATCH_PUBLIC_KEY_SIZE]);
    let public = Public::unchecked_from(public);

    Pair::verify(&signature, message, &public)
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_VrfInput {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_input_free(vrf_input_ptr: *const bandersnatch_VrfInput) {
    let _ = Box::from_raw(vrf_input_ptr as *mut VrfInput);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_input(
    domain_ptr: *const u8,
    domain_size: usize,
    message_ptr: *const u8,
    message_size: usize,
) -> *mut bandersnatch_VrfInput {
    let domain = slice::from_raw_parts(domain_ptr, domain_size);
    let message = slice::from_raw_parts(message_ptr, message_size);

    // make VrfInput in heap
    let input = Box::new(vrf::VrfInput::new(domain, message));

    // leak for static lifetime
    let input = Box::leak(input);

    input as *mut _ as *mut bandersnatch_VrfInput
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_VrfOutput {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_output_free(
    vrf_output_ptr: *const bandersnatch_VrfOutput,
) {
    let _ = Box::from_raw(vrf_output_ptr as *mut VrfOutput);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_output(
    secret_ptr: *const u8,
    input_ptr: *const bandersnatch_VrfInput,
) -> *mut bandersnatch_VrfOutput {
    let seed = *(secret_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);

    let secret = SecretKey::from_seed(&seed);

    let pair = Pair { secret, _seed: seed };

    let input = &*(input_ptr as *const vrf::VrfInput);

    let output = pair.vrf_output(input);

    let output = Box::new(output);

    let output = Box::leak(output);

    output as *mut _ as *mut bandersnatch_VrfOutput
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_output_encode(
    output_ptr: *const bandersnatch_VrfOutput,
    out_ptr: *mut u8,
) {
    let output = &*(output_ptr as *const vrf::VrfOutput);

    let encoded = output.0.encode();
    let _size = encoded.len();

    ptr::copy(encoded.as_ptr(), out_ptr, PREOUT_SERIALIZED_SIZE as usize);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_output_decode(
    encoded_ptr: *const u8,
) -> *const bandersnatch_VrfOutput {
    let encoded = &*(encoded_ptr as *mut [u8; 65]);

    let output = match VrfOutput::decode(&mut encoded.as_slice()) {
        Ok(x) => x,
        Err(_) => return null(),
    };

    let output = Box::new(output);

    let output = Box::leak(output);

    output as *mut _ as *mut bandersnatch_VrfOutput
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_VrfSignData {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_sign_data_free(
    sign_data_ptr: *const bandersnatch_VrfSignData,
) {
    let _ = Box::from_raw(sign_data_ptr as *mut VrfSignData);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_sign_data(
    transcript_label_ptr: *const u8,
    transcript_label_size: usize,
    transcript_data_ptrs: *const *const u8,
    transcript_data_sizes: *const usize,
    transcript_data_size: usize,
    inputs_ptr: *const *const bandersnatch_VrfInput,
    inputs_size: usize,
) -> *mut bandersnatch_VrfSignData {
    let transcript_label = slice::from_raw_parts(transcript_label_ptr, transcript_label_size);

    let transcript_data_ptrs = slice::from_raw_parts(transcript_data_ptrs, transcript_data_size);
    let transcript_data_sizes = slice::from_raw_parts(transcript_data_sizes, transcript_data_size);

    let transcript_data = transcript_data_ptrs
        .iter()
        .zip(transcript_data_sizes.iter())
        .map(|(ptr, size)| slice::from_raw_parts(*ptr, *size as _));

    let inputs = slice::from_raw_parts(inputs_ptr, inputs_size);

    let inputs: Vec<_> = inputs
        .iter()
        .map(|ptr| (*(*ptr as *mut VrfInput)).clone())
        .collect();

    let sign_data = vrf::VrfSignData::new_unchecked(transcript_label, transcript_data, inputs);

    // make VrfInput in heap
    let sign_data = Box::new(sign_data);

    // leak for static lifetime
    let sign_data = Box::leak(sign_data);

    sign_data as *mut _ as *mut bandersnatch_VrfSignData
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_sign_data_challenge(
    sign_data_ptr: *const bandersnatch_VrfSignData,
    bytes_ptr: *mut u8,
    bytes_size: usize,
) {
    let sign_data = &*(sign_data_ptr as *const vrf::VrfSignData);
    let bytes = slice::from_raw_parts_mut(bytes_ptr, bytes_size);

    match bytes_size {
        16 => {
            let x = sign_data.challenge::<16>();
            bytes.copy_from_slice(&x);
        }
        32 => {
            let x = sign_data.challenge::<32>();
            bytes.copy_from_slice(&x);
        }
        _ => panic!(),
    };
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_make_bytes(
    context_ptr: *const u8,
    context_size: usize,
    input_ptr: *const bandersnatch_VrfInput,
    output_ptr: *const bandersnatch_VrfOutput,
    bytes_ptr: *mut u8,
    bytes_size: usize,
) {
    let context = slice::from_raw_parts(context_ptr, context_size);
    let input = &*(input_ptr as *const vrf::VrfInput);
    let output = &*(output_ptr as *const vrf::VrfOutput);
    let bytes = slice::from_raw_parts_mut(bytes_ptr, bytes_size);

    match bytes_size {
        16 => {
            let x = output.make_bytes::<16>(context, input);
            bytes.copy_from_slice(&x);
        }
        32 => {
            let x = output.make_bytes::<32>(context, input);
            bytes.copy_from_slice(&x);
        }
        _ => panic!(),
    };
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_VrfSignature {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_signature_free(
    signature_ptr: *const bandersnatch_VrfSignature,
) {
    let _ = Box::from_raw(signature_ptr as *mut vrf::VrfSignature);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_signature_encode(
    signature_ptr: *const bandersnatch_VrfSignature,
    out_ptr: *mut u8,
) {
    let signature = &*(signature_ptr as *const vrf::VrfSignature);

    let encoded = signature.encode();

    ptr::copy(encoded.as_ptr(), out_ptr, encoded.len());
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_signature_decode(
    encoded_ptr: *mut u8,
    encoded_size: usize,
) -> *const bandersnatch_VrfSignature {
    let encoded = Vec::from_raw_parts(
        mem::transmute::<*const u8, *mut u8>(encoded_ptr),
        encoded_size,
        encoded_size,
    );

    let signature = vrf::VrfSignature::decode(&mut encoded.as_slice());

    encoded.leak();

    let signature = match signature {
        Ok(x) => x,
        Err(_) => return null(),
    };

    let signature = Box::new(signature);

    let signature = Box::leak(signature);

    signature as *mut _ as *mut bandersnatch_VrfSignature
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_sign(
    secret_ptr: *const u8,
    sign_data_ptr: *const bandersnatch_VrfSignData,
) -> *mut bandersnatch_VrfSignature {
    let seed = *(secret_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);

    let secret = SecretKey::from_seed(&seed);

    let pair = Pair { secret, _seed: seed };

    let sign_data = &*(sign_data_ptr as *const vrf::VrfSignData);

    let signature = pair.vrf_sign(&sign_data);

    let signature = Box::new(signature);

    let signature = Box::leak(signature);

    signature as *mut _ as *mut bandersnatch_VrfSignature
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_vrf_verify(
    signature_ptr: *const bandersnatch_VrfSignature,
    sign_data_ptr: *const bandersnatch_VrfSignData,
    public_ptr: *const u8,
) -> bool {
    let signature = &*(signature_ptr as *const vrf::VrfSignature);

    let sign_data = &*(sign_data_ptr as *const vrf::VrfSignData);

    let public = *(public_ptr as *const [u8; BANDERSNATCH_PUBLIC_KEY_SIZE]);
    let public = Public::unchecked_from(public);

    public.vrf_verify(sign_data, &signature)
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_RingContext {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_context_free(
    context_ptr: *const bandersnatch_RingContext,
) {
    let _ = Box::from_raw(context_ptr as *mut ring_vrf::RingContext<2048>);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_context_serialized_size(domain_size: u32) -> usize {
    ring_vrf::ring_context_serialized_size(domain_size)
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_vrf_context(
    encoded_ptr: *mut u8,
    encoded_size: usize,
) -> *const bandersnatch_RingContext {
    let encoded = Vec::from_raw_parts(encoded_ptr, encoded_size, encoded_size);

    let context = ring_vrf::RingContext::<2048>::decode(&mut encoded.as_slice());

    encoded.leak();

    let context = match context {
        Ok(context) => context,
        Err(_) => return null(),
    };

    let context = Box::new(context);

    let context = Box::leak(context);

    context as *mut _ as *mut bandersnatch_RingContext
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_RingProver {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_prover_free(prover_ptr: *const bandersnatch_RingProver) {
    let _ = Box::from_raw(prover_ptr as *mut ring_vrf::RingProver);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_prover(
    ring_context_ptr: *const bandersnatch_RingContext,
    keys_ptrs: *const *const u8,
    keys_size: usize,
    index: usize,
) -> *const bandersnatch_RingProver {
    let ring_context = &*(ring_context_ptr as *const ring_vrf::RingContext<2048>);

    let keys = slice::from_raw_parts(keys_ptrs, keys_size);

    let keys: Vec<_> = keys
        .iter()
        .map(|ptr| &*(*ptr as *const [u8; PUBLIC_SERIALIZED_SIZE]))
        .map(|data| Public::unchecked_from(data.clone()))
        .collect();

    let prover = match ring_context.prover(keys.as_slice(), index) {
        Some(prover) => prover,
        None => return null(),
    };

    let prover = Box::new(prover);

    let prover = Box::leak(prover);

    prover as *mut _ as *mut bandersnatch_RingProver
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_RingVerifier {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_verifier_free(
    verifier_ptr: *const bandersnatch_RingVerifier,
) {
    let _ = Box::from_raw(verifier_ptr as *mut ring_vrf::RingVerifier);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_verifier(
    ring_context_ptr: *const bandersnatch_RingContext,
    keys_ptrs: *const *const u8,
    keys_size: usize,
) -> *const bandersnatch_RingVerifier {
    let ring_context = &*(ring_context_ptr as *const ring_vrf::RingContext<2048>);

    let keys = slice::from_raw_parts(keys_ptrs, keys_size);

    let keys: Vec<_> = keys
        .iter()
        .map(|ptr| &*(*ptr as *const [u8; PUBLIC_SERIALIZED_SIZE]))
        .map(|data| Public::unchecked_from(data.clone()))
        .collect();

    let verifier = match ring_context.verifier(keys.as_slice()) {
        Some(verifier) => verifier,
        None => return null(),
    };

    let verifier = Box::new(verifier);

    let verifier = Box::leak(verifier);

    verifier as *mut _ as *mut bandersnatch_RingVerifier
}

#[allow(non_camel_case_types)]
pub enum bandersnatch_RingVrfSignature {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_vrf_signature_free(
    signature_ptr: *const bandersnatch_RingVrfSignature,
) {
    let _ = Box::from_raw(signature_ptr as *mut ring_vrf::RingVrfSignature);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_vrf_signature_encode(
    signature_ptr: *const bandersnatch_RingVrfSignature,
    out_ptr: *mut u8,
) {
    let signature = &*(signature_ptr as *const ring_vrf::RingVrfSignature);

    let encoded = signature.encode();

    ptr::copy(encoded.as_ptr(), out_ptr, encoded.len());
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_vrf_signature_decode(
    encoded_ptr: *const u8,
    encoded_size: usize,
) -> *const bandersnatch_RingVrfSignature {
    let encoded = Vec::from_raw_parts(
        mem::transmute::<*const u8, *mut u8>(encoded_ptr),
        encoded_size,
        encoded_size,
    );

    let signature = RingVrfSignature::decode(&mut encoded.as_slice());

    encoded.leak();

    let signature = match signature {
        Ok(x) => x,
        Err(_) => return null(),
    };

    let signature = Box::new(signature);

    let signature = Box::leak(signature);

    signature as *mut _ as *mut bandersnatch_RingVrfSignature
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_vrf_sign(
    secret_ptr: *const u8,
    sign_data_ptr: *const bandersnatch_VrfSignData,
    prover_ptr: *const bandersnatch_RingProver,
) -> *mut bandersnatch_RingVrfSignature {
    let seed = *(secret_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);

    let secret = SecretKey::from_seed(&seed);

    let pair = Pair { secret, _seed: seed };

    let sign_data = &*(sign_data_ptr as *const VrfSignData);

    let prover = &*(prover_ptr as *const RingProver);

    let signature = pair.ring_vrf_sign(sign_data, prover);

    let signature = Box::new(signature);

    let signature = Box::leak(signature);

    signature as *mut _ as *mut bandersnatch_RingVrfSignature
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ring_vrf_verify(
    signature_ptr: *const bandersnatch_RingVrfSignature,
    sign_data_ptr: *const bandersnatch_VrfSignData,
    verifier_ptr: *const bandersnatch_RingVerifier,
) -> bool {
    let signature = &*(signature_ptr as *const ring_vrf::RingVrfSignature);

    let sign_data = &*(sign_data_ptr as *const vrf::VrfSignData);

    let verifier = &*(verifier_ptr as *const RingVerifier);

    signature.ring_vrf_verify(sign_data, verifier)
}
