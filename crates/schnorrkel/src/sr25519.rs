use std::cmp::min;
use std::os::raw::c_ulong;
use std::ptr;
use std::slice;

use crate::bitfield::CoreBitfield;
use crate::constants::ASSIGNED_CORE_CONTEXT;
use crate::constants::ASSIGNED_CORE_CONTEXT_V2;
use crate::constants::CORE_RANDOMNESS_CONTEXT;
use crate::constants::CORE_RANDOMNESS_CONTEXT_V2;
use crate::constants::MAX_MODULO_SAMPLES;
use crate::constants::RELAY_VRF_DELAY_CONTEXT;
use crate::constants::RELAY_VRF_MODULO_CONTEXT;
use crate::constants::RELAY_VRF_MODULO_CONTEXT_V2;
use crate::constants::RELAY_VRF_STORY_CONTEXT;
use crate::constants::RELAY_VRF_STORY_SIZE;
use crate::constants::SR25519_CHAINCODE_SIZE;
use crate::constants::SR25519_KEYPAIR_SIZE;
use crate::constants::SR25519_PUBLIC_SIZE;
use crate::constants::SR25519_SECRET_SIZE;
use crate::constants::SR25519_SEED_SIZE;
use crate::constants::SR25519_SIGNATURE_SIZE;
use crate::constants::SR25519_VRF_OUTPUT_SIZE;
use crate::constants::SR25519_VRF_PROOF_SIZE;
use crate::constants::SR25519_VRF_RAW_OUTPUT_SIZE;
use crate::constants::SR25519_VRF_THRESHOLD_SIZE;
use crate::constants::TRANCHE_RANDOMNESS_CONTEXT;
pub use merlin::Transcript;
use parity_scale_codec::Encode;
use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha20Rng;
use schnorrkel::vrf::{VRFProofBatchable, VRFSigningTranscript};
use schnorrkel::{
    context::signing_context,
    derive::{ChainCode, Derivation, CHAIN_CODE_LENGTH},
    vrf::{VRFInOut, VRFOutput, VRFProof},
    ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey, Signature, SignatureError,
    SignatureResult,
};
use std::convert::TryInto;
use std::fmt::{Error, Formatter};

macro_rules! return_if_err {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => return convert_error(&err).into(),
        }
    };
}

// cbindgen has an issue with macros, so define it outside,
// otherwise it would've been possible to avoid duplication of macro variant list
/// status code of a function call
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Sr25519SignatureResult {
    /// Success
    Ok,
    /// A signature verification equation failed.
    ///
    /// We emphasise that all variants represent a failed signature,
    /// not only this one.
    EquationFalse,
    /// Invalid point provided, usually to `verify` methods.
    PointDecompressionError,
    /// Invalid scalar provided, usually to `Signature::from_bytes`.
    ScalarFormatError,
    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass a string specifying the `name` of the type
    /// which is returning the error, and the `length` in bytes which
    /// its constructor expects.
    BytesLengthError,
    /// Signature not marked as schnorrkel, maybe try ed25519 instead.
    NotMarkedSchnorrkel,
    /// There is no record of the preceeding multi-signautre protocol
    /// stage for the specified public key.
    MuSigAbsent,
    /// For this public key, there are either conflicting records for
    /// the preceeding multi-signautre protocol stage or else duplicate
    /// duplicate records for the current stage.
    MuSigInconsistent,
}

/// converts from schnorrkel::SignatureError
/// to Sr25519SignatureResult (which is exported to C header)
fn convert_error(err: &SignatureError) -> Sr25519SignatureResult {
    match err {
        SignatureError::EquationFalse => Sr25519SignatureResult::EquationFalse,
        SignatureError::PointDecompressionError => Sr25519SignatureResult::PointDecompressionError,
        SignatureError::ScalarFormatError => Sr25519SignatureResult::ScalarFormatError,
        SignatureError::BytesLengthError {
            name: _,
            description: _,
            length: _,
        } => Sr25519SignatureResult::BytesLengthError,
        SignatureError::MuSigAbsent { musig_stage: _ } => Sr25519SignatureResult::MuSigAbsent,
        SignatureError::MuSigInconsistent {
            musig_stage: _,
            duplicate: _,
        } => Sr25519SignatureResult::MuSigInconsistent,
        SignatureError::NotMarkedSchnorrkel => Sr25519SignatureResult::NotMarkedSchnorrkel,
    }
}

/// We must make sure that this is the same as declared in the substrate source code.
pub const BABE_VRF_PREFIX: &'static [u8] = b"substrate-babe-vrf";
const SIGNING_CTX: &'static [u8] = b"substrate";

/// ChainCode construction helper
fn create_cc(data: &[u8]) -> ChainCode {
    let mut cc = [0u8; CHAIN_CODE_LENGTH];

    cc.copy_from_slice(&data);

    ChainCode(cc)
}

/// Keypair helper function.
fn create_from_seed(seed: &[u8]) -> Keypair {
    match MiniSecretKey::from_bytes(seed) {
        Ok(mini) => return mini.expand_to_keypair(ExpansionMode::Ed25519),
        Err(_) => panic!("Provided seed is invalid."),
    }
}

/// Keypair helper function.
fn create_from_pair(pair: &[u8]) -> Keypair {
    match Keypair::from_bytes(pair) {
        Ok(pair) => return pair,
        Err(_) => panic!("Provided pair is invalid: {:?}", pair),
    }
}

/// PublicKey helper
fn create_public(public: &[u8]) -> PublicKey {
    match PublicKey::from_bytes(public) {
        Ok(public) => return public,
        Err(_) => panic!("Provided public key is invalid."),
    }
}

/// SecretKey helper
fn create_secret(secret: &[u8]) -> SecretKey {
    match SecretKey::from_bytes(secret) {
        Ok(secret) => return secret,
        Err(_) => panic!("Provided private key is invalid."),
    }
}

// Combines the relay VRF story with a sample number if any.
fn relay_vrf_modulo_transcript_inner(
    mut transcript: Transcript,
    relay_vrf_story: RelayVRFStory,
    sample: Option<u32>,
) -> Transcript {
    transcript.append_message(b"RC-VRF", &relay_vrf_story.data);

    if let Some(sample) = sample {
        sample.using_encoded(|s| transcript.append_message(b"sample", s));
    }

    transcript
}

fn relay_vrf_modulo_transcript(relay_vrf_story: RelayVRFStory, sample: u32) -> Transcript {
    // combine the relay VRF story with a sample number.
    let mut t = Transcript::new(RELAY_VRF_MODULO_CONTEXT);
    t.append_message(b"RC-VRF", &relay_vrf_story.data);

    let buf = sample.to_le_bytes();
    t.append_message(b"sample", &buf[..]);

    t
}

fn relay_vrf_modulo_transcript_v2(relay_vrf_story: RelayVRFStory) -> Transcript {
    relay_vrf_modulo_transcript_inner(
        Transcript::new(RELAY_VRF_MODULO_CONTEXT_V2),
        relay_vrf_story,
        None,
    )
}

/// Generates `num_samples` randomly from (0..max_cores) range
///
/// Note! The algorithm can't change because validators on the other
/// side won't be able to check the assignments until they update.
/// This invariant is tested with `generate_samples_invariant`, so the
/// tests will catch any subtle changes in the implementation of this function
/// and its dependencies.
fn generate_samples(
    mut rand_chacha: ChaCha20Rng,
    num_samples: usize,
    max_cores: usize,
) -> Box<[u32]> {
    let num_samples = min(MAX_MODULO_SAMPLES, min(num_samples, max_cores));

    let mut random_cores = (0..max_cores as u32)
        .map(|val| val.into())
        .collect::<Vec<u32>>();
    let (samples, _) = random_cores.partial_shuffle(&mut rand_chacha, num_samples as usize);
    samples.into_iter().map(|val| *val).collect::<Box<[u32]>>()
}

/// Takes the VRF output as input and returns a Vec of cores the validator is assigned
/// to as a tranche0 checker.
fn relay_vrf_modulo_cores(
    vrf_in_out: &VRFInOut,
    // Configuration - `relay_vrf_modulo_samples`.
    num_samples: u32,
    // Configuration - `n_cores`.
    max_cores: u32,
) -> Box<[u32]> {
    let rand_chacha = ChaCha20Rng::from_seed(
        vrf_in_out.make_bytes::<<ChaCha20Rng as SeedableRng>::Seed>(CORE_RANDOMNESS_CONTEXT_V2),
    );
    generate_samples(rand_chacha, num_samples as usize, max_cores as usize)
}

fn relay_vrf_modulo_core(vrf_in_out: &VRFInOut, n_cores: u32) -> u32 {
    let bytes: [u8; 4] = vrf_in_out.make_bytes(CORE_RANDOMNESS_CONTEXT);

    // interpret as little-endian u32.
    let random_core = u32::from_le_bytes(bytes) % n_cores;
    random_core
}

fn relay_vrf_delay_transcript(relay_vrf_story: RelayVRFStory, core_index: u32) -> Transcript {
    let mut t = Transcript::new(RELAY_VRF_DELAY_CONTEXT);
    t.append_message(b"RC-VRF", &relay_vrf_story.data);

    let buf = core_index.to_le_bytes();
    t.append_message(b"core", &buf[..]);

    t
}

fn relay_vrf_delay_tranche(
    vrf_in_out: &VRFInOut,
    num_delay_tranches: u32,
    zeroth_delay_tranche_width: u32,
) -> u32 {
    let bytes: [u8; 4] = vrf_in_out.make_bytes(TRANCHE_RANDOMNESS_CONTEXT);

    // interpret as little-endian u32 and reduce by the number of tranches.
    let wide_tranche =
        u32::from_le_bytes(bytes) % (num_delay_tranches + zeroth_delay_tranche_width);

    // Consolidate early results to tranche zero so tranche zero is extra wide.
    wide_tranche.saturating_sub(zeroth_delay_tranche_width)
}

fn assigned_core_transcript(core_index: u32) -> Transcript {
    let mut t = Transcript::new(ASSIGNED_CORE_CONTEXT);
    let buf = core_index.to_le_bytes();
    t.append_message(b"core", &buf[..]);
    t
}

fn assigned_cores_transcript(core_bitfield: &CoreBitfield) -> Transcript {
    let mut t = Transcript::new(ASSIGNED_CORE_CONTEXT_V2);
    core_bitfield.using_encoded(|s| t.append_message(b"cores", s));
    t
}

/// Perform a derivation on a secret
///
/// * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_keypair_hard(
    keypair_out: *mut u8,
    pair_ptr: *const u8,
    cc_ptr: *const u8,
) {
    let pair = slice::from_raw_parts(pair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE as usize);
    let kp = create_from_pair(pair)
        .secret
        .hard_derive_mini_secret_key(Some(create_cc(cc)), &[])
        .0
        .expand_to_keypair(ExpansionMode::Ed25519);

    ptr::copy(
        kp.to_bytes().as_ptr(),
        keypair_out,
        SR25519_KEYPAIR_SIZE as usize,
    );
}

/// Perform a derivation on a secret
///
/// * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_keypair_soft(
    keypair_out: *mut u8,
    pair_ptr: *const u8,
    cc_ptr: *const u8,
) {
    let pair = slice::from_raw_parts(pair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE as usize);
    let kp = create_from_pair(pair)
        .derived_key_simple(create_cc(cc), &[])
        .0;

    ptr::copy(
        kp.to_bytes().as_ptr(),
        keypair_out,
        SR25519_KEYPAIR_SIZE as usize,
    );
}

/// Perform a derivation on a publicKey
///
/// * pubkey_out: pre-allocated output buffer of SR25519_PUBLIC_SIZE bytes
/// * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_public_soft(
    pubkey_out: *mut u8,
    public_ptr: *const u8,
    cc_ptr: *const u8,
) {
    let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE as usize);
    let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE as usize);
    let p = create_public(public)
        .derived_key_simple(create_cc(cc), &[])
        .0;
    ptr::copy(
        p.to_bytes().as_ptr(),
        pubkey_out,
        SR25519_PUBLIC_SIZE as usize,
    );
}

/// Generate a key pair.
///
/// * keypair_out: keypair [32b key | 32b nonce | 32b public], pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * seed: generation seed - input buffer of SR25519_SEED_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_keypair_from_seed(keypair_out: *mut u8, seed_ptr: *const u8) {
    let seed = slice::from_raw_parts(seed_ptr, SR25519_SEED_SIZE as usize);
    let kp = create_from_seed(seed);
    ptr::copy(
        kp.to_bytes().as_ptr(),
        keypair_out,
        SR25519_KEYPAIR_SIZE as usize,
    );
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * signature_out: output buffer of ED25519_SIGNATURE_SIZE bytes
/// * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
/// * secret_ptr: private key (secret) - input buffer of SR25519_SECRET_SIZE bytes
/// * message_ptr: Arbitrary message; input buffer of size message_length
/// * message_length: Length of a message
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_sign(
    signature_out: *mut u8,
    public_ptr: *const u8,
    secret_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
) {
    let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE as usize);
    let secret = slice::from_raw_parts(secret_ptr, SR25519_SECRET_SIZE as usize);
    let message = cpp::from_raw_parts(message_ptr, message_length as usize);

    let sig = create_secret(secret).sign_simple(SIGNING_CTX, message, &create_public(public));

    ptr::copy(
        sig.to_bytes().as_ptr(),
        signature_out,
        SR25519_SIGNATURE_SIZE as usize,
    );
}

/// Verify a message and its corresponding against a public key;
///
/// * signature_ptr: verify this signature
/// * message_ptr: Arbitrary message; input buffer of message_length bytes
/// * message_length: Message size
/// * public_ptr: verify with this public key; input buffer of SR25519_PUBLIC_SIZE bytes
///
/// * returned true if signature is valid, false otherwise
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_verify_deprecated(
    signature_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
    public_ptr: *const u8,
) -> bool {
    let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE as usize);
    let signature = slice::from_raw_parts(signature_ptr, SR25519_SIGNATURE_SIZE as usize);
    let message = cpp::from_raw_parts(message_ptr, message_length as usize);

    create_public(public)
        .verify_simple_preaudit_deprecated(SIGNING_CTX, message, &signature)
        .is_ok()
}

/// Verify a message and its corresponding against a public key;
///
/// * signature_ptr: verify this signature
/// * message_ptr: Arbitrary message; input buffer of message_length bytes
/// * message_length: Message size
/// * public_ptr: verify with this public key; input buffer of SR25519_PUBLIC_SIZE bytes
///
/// * returned true if signature is valid, false otherwise
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_verify(
    signature_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
    public_ptr: *const u8,
) -> bool {
    let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE as usize);
    let signature = slice::from_raw_parts(signature_ptr, SR25519_SIGNATURE_SIZE as usize);
    let message = cpp::from_raw_parts(message_ptr, message_length as usize);
    let signature = match Signature::from_bytes(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    create_public(public)
        .verify_simple(SIGNING_CTX, message, &signature)
        .is_ok()
}

#[repr(C)]
/// Result of a VRF
pub struct VrfResult {
    /// status code
    pub result: Sr25519SignatureResult,
    /// is the output of the function less than the provided threshold
    pub is_less: bool,
}

#[repr(C)]
pub struct VrfResultExtra {
    pub result: Sr25519SignatureResult,
    pub input_bytes: [u8; 32],
    pub output_bytes: [u8; 32],
}

impl VrfResult {
    fn create_err(err: &SignatureError) -> VrfResult {
        VrfResult {
            is_less: false,
            result: convert_error(&err),
        }
    }

    fn create_val(is_less: bool) -> VrfResult {
        VrfResult {
            is_less,
            result: Sr25519SignatureResult::Ok,
        }
    }
}

impl std::fmt::Debug for VrfResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str("VrfResult { ")?;
        f.write_str(self.is_less.to_string().as_str())?;
        f.write_str(", ")?;
        write!(f, "{:?}", self)?;
        f.write_str(" }")?;
        Ok(())
    }
}

/// Sign the provided message using a Verifiable Random Function and
/// if the result is less than \param limit provide the proof
/// @param out_and_proof_ptr pointer to output array, where the VRF out and proof will be written
/// @param keypair_ptr byte representation of the keypair that will be used during signing
/// @param message_ptr byte array to be signed
/// @param limit_ptr byte array, must be 16 bytes long
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_sign_if_less(
    out_and_proof_ptr: *mut u8,
    keypair_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
    limit_ptr: *const u8,
) -> VrfResult {
    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let keypair = create_from_pair(keypair_bytes);
    let message = cpp::from_raw_parts(message_ptr, message_length as usize);

    let limit = slice::from_raw_parts(limit_ptr, SR25519_VRF_THRESHOLD_SIZE as usize);
    let mut limit_arr: [u8; SR25519_VRF_THRESHOLD_SIZE as usize] = Default::default();
    limit_arr.copy_from_slice(&limit[0..SR25519_VRF_THRESHOLD_SIZE as usize]);

    let (io, proof, _) = keypair.vrf_sign(signing_context(SIGNING_CTX).bytes(message));
    let limit_int = u128::from_le_bytes(limit_arr);

    let raw_out_bytes =
        io.make_bytes::<[u8; SR25519_VRF_RAW_OUTPUT_SIZE as usize]>(BABE_VRF_PREFIX);
    let check = u128::from_le_bytes(raw_out_bytes) < limit_int;

    ptr::copy(
        io.to_output().as_bytes().as_ptr(),
        out_and_proof_ptr,
        SR25519_VRF_OUTPUT_SIZE as usize,
    );
    ptr::copy(
        proof.to_bytes().as_ptr(),
        out_and_proof_ptr.add(SR25519_VRF_OUTPUT_SIZE as usize),
        SR25519_VRF_PROOF_SIZE as usize,
    );

    VrfResult::create_val(check)
}

impl From<Sr25519SignatureResult> for VrfResult {
    fn from(value: Sr25519SignatureResult) -> Self {
        VrfResult {
            result: value,
            is_less: false,
        }
    }
}

impl From<Sr25519SignatureResult> for VrfResultExtra {
    fn from(value: Sr25519SignatureResult) -> Self {
        VrfResultExtra {
            result: value,
            input_bytes: [0; 32],
            output_bytes: [0; 32],
        }
    }
}

/// Verify a signature produced by a VRF with its original input and the corresponding proof and
/// check if the result of the function is less than the threshold.
/// @note If errors, is_less field of the returned structure is not meant to contain a valid value
/// @param public_key_ptr byte representation of the public key that was used to sign the message
/// @param message_ptr the orignal signed message
/// @param output_ptr the signature
/// @param proof_ptr the proof of the signature
/// @param threshold_ptr the threshold to be compared against
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_verify(
    public_key_ptr: *const u8,
    message_ptr: *const u8,
    message_length: c_ulong,
    output_ptr: *const u8,
    proof_ptr: *const u8,
    threshold_ptr: *const u8,
) -> VrfResult {
    let public_key = create_public(slice::from_raw_parts(
        public_key_ptr,
        SR25519_PUBLIC_SIZE as usize,
    ));
    let message = cpp::from_raw_parts(message_ptr, message_length as usize);
    let ctx = signing_context(SIGNING_CTX).bytes(message);
    let given_out = return_if_err!(VRFOutput::from_bytes(slice::from_raw_parts(
        output_ptr,
        SR25519_VRF_OUTPUT_SIZE as usize,
    )));
    let given_proof = return_if_err!(VRFProof::from_bytes(slice::from_raw_parts(
        proof_ptr,
        SR25519_VRF_PROOF_SIZE as usize,
    )));
    let (in_out, proof) =
        return_if_err!(public_key.vrf_verify(ctx.clone(), &given_out, &given_proof));
    let raw_output =
        in_out.make_bytes::<[u8; SR25519_VRF_RAW_OUTPUT_SIZE as usize]>(BABE_VRF_PREFIX);

    let threshold = slice::from_raw_parts(threshold_ptr, SR25519_VRF_THRESHOLD_SIZE as usize);
    let threshold_arr: [u8; SR25519_VRF_THRESHOLD_SIZE as usize] = match threshold.try_into() {
        Ok(val) => val,
        Err(err) => {
            return VrfResult {
                result: Sr25519SignatureResult::BytesLengthError,
                is_less: false,
            }
        }
    };
    let threshold_int = u128::from_le_bytes(threshold_arr);

    let check = u128::from_le_bytes(raw_output) < threshold_int;

    let decomp_proof = match proof.shorten_vrf(&public_key, ctx.clone(), &in_out.to_output()) {
        Ok(val) => val,
        Err(e) => return VrfResult::create_err(&e),
    };
    if in_out.to_output() == given_out && decomp_proof == given_proof {
        VrfResult::create_val(check)
    } else {
        VrfResult::create_err(&SignatureError::EquationFalse)
    }
}

/// VRFOutput C representation. Can be used from C-code to deliver data into rust.
#[repr(C)]
#[derive(Clone)]
pub struct VRFCOutput {
    /// data array with VRFOutput
    pub data: [u8; SR25519_VRF_OUTPUT_SIZE],
}

/// VRFProof C representation. Can be used from C-code to deliver data into rust.
#[repr(C)]
#[derive(Clone)]
pub struct VRFCProof {
    /// data array with VRFProof
    pub data: [u8; SR25519_VRF_PROOF_SIZE],
}

/// RelayVRFStory C representation. Can be used from C-code to deliver data into rust.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RelayVRFStory {
    /// data array with RelayVRFStory
    pub data: [u8; RELAY_VRF_STORY_SIZE],
}

/// Computes the randomness of provided transcript and vrf_output
/// @param public_key_ptr - pointer to public key
/// @param transcript_data - pointer to a Strobe object, which is an internal representation of the transcript data
/// @param vrf_output - byte array with vrf_output
/// @param out_relay_vrf_story - pointer to output array with data
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_compute_randomness(
    public_key_ptr: *const u8,
    transcript_data: *mut Strobe128,
    vrf_output: *const VRFCOutput,
    out_relay_vrf_story: *mut RelayVRFStory,
) -> Sr25519SignatureResult {
    let pk = create_public(slice::from_raw_parts(
        public_key_ptr,
        SR25519_PUBLIC_SIZE as usize,
    ));
    let t = std::mem::transmute::<*mut Strobe128, &mut Transcript>(transcript_data);
    let v = std::mem::transmute::<*const VRFCOutput, &VRFOutput>(vrf_output);

    let vrf_in_out = return_if_err!(v.attach_input_hash(&pk, t));
    (*out_relay_vrf_story).data = vrf_in_out.make_bytes(RELAY_VRF_STORY_CONTEXT);
    return Sr25519SignatureResult::Ok;
}

/// This is literally a copy of Strobe128 from merlin lib
/// Have to copy it as a workaround for passing a strobe object from C code
/// Because the orignal Strobe128 structure is private and it is impossible to initialize it from
/// a ready byte array
#[repr(C)]
#[derive(Clone)]
pub struct Strobe128 {
    state: [u8; 200],
    pos: u8,
    pos_begin: u8,
    cur_flags: u8,
}

/// Sign the provided transcript using a Verifiable Random Function and
/// if the result is less than \param limit provide the proof
/// @param out_and_proof_ptr - pointer to output array, where the VRF out and proof will be written
/// @param keypair_ptr - byte representation of the keypair that will be used during signing
/// @param transcript_data - pointer to a Strobe object, which is an internal representation of the transcript data
/// @param limit_ptr - byte array, must be 16 bytes long
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_sign_transcript(
    out_and_proof_ptr: *mut u8,
    keypair_ptr: *const u8,
    transcript_data: *const Strobe128,
    limit_ptr: *const u8,
) -> VrfResult {
    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let keypair = create_from_pair(keypair_bytes);

    let limit = slice::from_raw_parts(limit_ptr, SR25519_VRF_THRESHOLD_SIZE as usize);
    let mut limit_arr: [u8; SR25519_VRF_THRESHOLD_SIZE as usize] = Default::default();
    limit_arr.copy_from_slice(&limit[0..SR25519_VRF_THRESHOLD_SIZE as usize]);

    let transcript = std::mem::transmute::<*const Strobe128, &mut Transcript>(transcript_data);

    let (io, proof, _) = keypair.vrf_sign(transcript);
    let limit_int = u128::from_le_bytes(limit_arr);

    let raw_out_bytes =
        io.make_bytes::<[u8; SR25519_VRF_RAW_OUTPUT_SIZE as usize]>(BABE_VRF_PREFIX);
    let check = u128::from_le_bytes(raw_out_bytes) < limit_int;

    ptr::copy(
        io.to_output().as_bytes().as_ptr(),
        out_and_proof_ptr,
        SR25519_VRF_OUTPUT_SIZE as usize,
    );
    ptr::copy(
        proof.to_bytes().as_ptr(),
        out_and_proof_ptr.add(SR25519_VRF_OUTPUT_SIZE as usize),
        SR25519_VRF_PROOF_SIZE as usize,
    );

    VrfResult::create_val(check)
}

fn vrf_verify_transcript<T>(
    pk: PublicKey,
    transcript: T,
    output_ptr: *const u8,
    proof_ptr: *const u8,
) -> SignatureResult<(VRFInOut, VRFProofBatchable)>
where
    T: VRFSigningTranscript,
{
    let (out, proof) = unsafe {
        let out = VRFOutput::from_bytes(slice::from_raw_parts(
            output_ptr,
            SR25519_VRF_OUTPUT_SIZE as usize,
        ))?;
        let proof = VRFProof::from_bytes(slice::from_raw_parts(
            proof_ptr,
            SR25519_VRF_PROOF_SIZE as usize,
        ))?;

        (out, proof)
    };
    pk.vrf_verify(transcript, &out, &proof)
}

/// Verify a signature produced by a VRF with its original input transcript and the corresponding proof and
/// check if the result of the function is less than the threshold.
/// @note If errors, is_less field of the returned structure is not meant to contain a valid value
/// @param public_key_ptr - byte representation of the public key that was used to sign the message
/// @param transcript_data - pointer to a Strobe object, which is an internal representation
///                          of the signed transcript data
/// @param output_ptr - the signature
/// @param proof_ptr - the proof of the signature
/// @param threshold_ptr - the threshold to be compared against
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_verify_transcript(
    public_key_ptr: *const u8,
    transcript_data: *const Strobe128,
    output_ptr: *const u8,
    proof_ptr: *const u8,
    threshold_ptr: *const u8,
) -> VrfResult {
    let public_key = create_public(slice::from_raw_parts(
        public_key_ptr,
        SR25519_PUBLIC_SIZE as usize,
    ));
    let transcript = std::mem::transmute::<*const Strobe128, &mut Transcript>(transcript_data);
    let (in_out, _) = return_if_err!(vrf_verify_transcript(
        public_key, transcript, output_ptr, proof_ptr
    ));
    let raw_output =
        in_out.make_bytes::<[u8; SR25519_VRF_RAW_OUTPUT_SIZE as usize]>(BABE_VRF_PREFIX);

    let threshold = slice::from_raw_parts(threshold_ptr, SR25519_VRF_THRESHOLD_SIZE as usize);
    let threshold_arr: [u8; SR25519_VRF_THRESHOLD_SIZE as usize] = match threshold.try_into() {
        Ok(val) => val,
        Err(err) => {
            return VrfResult {
                result: Sr25519SignatureResult::BytesLengthError,
                is_less: false,
            }
        }
    };
    let threshold_int = u128::from_le_bytes(threshold_arr);

    let check = u128::from_le_bytes(raw_output) < threshold_int;
    VrfResult::create_val(check)
}

/// Computes output and proof for valid VRF assignment certificate.
/// @param keypair_ptr - byte repr of valid keypair for signing
/// @param relay_vrf_modulo_samples - number of samples for transcript
/// @param n_cores - number of available cores
/// @param relay_vrf_story - relay vrf story
/// @param leaving_cores_ptr - array of leaving cores
/// @param leaving_cores_num - number of elements in leaving cores array
/// @param cert_output - certificate output
/// @param cert_proof - certificate proof
/// @param cores_out - output leaving cores
/// @param cores_out_sz - output leaving cores count
/// @param cores_cap - output leaving cores capacity(need to dealloc)
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_relay_vrf_modulo_assignments_cert_v2(
    keypair_ptr: *const u8,
    relay_vrf_modulo_samples: u32,
    n_cores: u32,
    relay_vrf_story: *const RelayVRFStory,
    leaving_cores_ptr: *const u32,
    leaving_cores_num: u32,
    cert_output: *mut VRFCOutput,
    cert_proof: *mut VRFCProof,
    cores_out: *mut *mut u32,
    cores_out_sz: *mut u64,
) -> bool {
    assert!(!cert_output.is_null());
    assert!(!cert_proof.is_null());
    assert!(!cores_out.is_null());
    assert!(!cores_out_sz.is_null());

    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let assignments_key = create_from_pair(keypair_bytes);

    let leaving_cores = cpp::from_raw_parts(leaving_cores_ptr, leaving_cores_num as usize);

    let relay_vrf_story =
        std::mem::transmute::<*const RelayVRFStory, &RelayVRFStory>(relay_vrf_story);

    let cert_output = std::mem::transmute::<*mut VRFCOutput, &mut VRFCOutput>(cert_output);
    let cert_proof = std::mem::transmute::<*mut VRFCProof, &mut VRFCProof>(cert_proof);

    let mut assigned_cores: Box<[u32]> = Box::new([]);
    let maybe_assignment = {
        let assigned_cores = &mut assigned_cores;
        assignments_key.vrf_sign_extra_after_check(
            relay_vrf_modulo_transcript_v2(relay_vrf_story.clone()),
            |vrf_in_out| {
                *assigned_cores =
                    relay_vrf_modulo_cores(&vrf_in_out, relay_vrf_modulo_samples, n_cores)
                        .iter()
                        .filter(|core| leaving_cores.contains(&core))
                        .copied()
                        .collect::<Box<[u32]>>();

                if !assigned_cores.is_empty() {
                    let assignment_bitfield: CoreBitfield = assigned_cores
                        .clone()
                        .into_vec()
                        .try_into()
                        .expect("Just checked `!assigned_cores.is_empty()`; qed");

                    Some(assigned_cores_transcript(&assignment_bitfield))
                } else {
                    None
                }
            },
        )
    };

    if let Some((vrf_in_out, vrf_proof, _)) = maybe_assignment {
        let len = assigned_cores.len();

        *cores_out_sz = assigned_cores.len() as u64;
        *cores_out = (*Box::<[u32]>::into_raw(assigned_cores)).as_mut_ptr();

        cert_output.data = *vrf_in_out.as_output_bytes();
        cert_proof.data = vrf_proof.to_bytes();
        true
    } else {
        false
    }
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_relay_vrf_modulo_core(
    input_bytes: &[u8; 32],
    output_bytes: &[u8; 32],
    n_cores: u32,
) -> u32 {

    // Construct CompressedRistretto from the byte slices.
    pub use schnorrkel::points::RistrettoBoth;

    let input = RistrettoBoth::from_bytes(input_bytes).unwrap();
    let output = RistrettoBoth::from_bytes(output_bytes).unwrap();

    // Create the VRFInOut struct.
    let vrf_in_out = VRFInOut { input, output };

    // Call relay_vrf_modulo_core.
    relay_vrf_modulo_core(&vrf_in_out, n_cores)
}

/// Clears allocated memory
/// @param cores_out - leaving cores
/// @param cores_out_sz - leaving cores count
/// @param cores_cap - leaving cores capacity
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_clear_assigned_cores_v2(cores_out: *mut u32, cores_out_sz: u64) {
    let _ = Box::<[u32]>::from(cpp::from_raw_parts(cores_out, cores_out_sz as usize));
}

/// Computes output and proof for valid VRF assignment certificate.
/// @param keypair_ptr - byte repr of valid keypair for signing
/// @param rvm_sample - sample value for transcript
/// @param n_cores - number of available cores
/// @param relay_vrf_story - relay vrf story
/// @param leaving_cores_ptr - array of leaving cores
/// @param leaving_cores_num - number of elements in leaving cores array
/// @param cert_output - certificate output
/// @param cert_proof - certificate proof
/// @param core_out - output leaving core
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_relay_vrf_modulo_assignments_cert(
    keypair_ptr: *const u8,
    rvm_sample: u32,
    n_cores: u32,
    relay_vrf_story: *const RelayVRFStory,
    leaving_cores_ptr: *const u32,
    leaving_cores_num: u32,
    cert_output: *mut VRFCOutput,
    cert_proof: *mut VRFCProof,
    core_out: *mut u32,
) -> bool {
    assert!(!cert_output.is_null());
    assert!(!cert_proof.is_null());
    assert!(!core_out.is_null());

    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let assignments_key = create_from_pair(keypair_bytes);

    let leaving_cores = cpp::from_raw_parts(leaving_cores_ptr, leaving_cores_num as usize);

    let mut core = u32::default();
    let relay_vrf_story =
        std::mem::transmute::<*const RelayVRFStory, &RelayVRFStory>(relay_vrf_story);

    let cert_output = std::mem::transmute::<*mut VRFCOutput, &mut VRFCOutput>(cert_output);
    let cert_proof = std::mem::transmute::<*mut VRFCProof, &mut VRFCProof>(cert_proof);

    let maybe_assignment = {
        // Extra scope to ensure borrowing instead of moving core
        // into closure.
        let core = &mut core;
        assignments_key.vrf_sign_extra_after_check(
            relay_vrf_modulo_transcript(relay_vrf_story.clone(), rvm_sample),
            |vrf_in_out| {
                *core = relay_vrf_modulo_core(&vrf_in_out, n_cores);
                if let Some(lc) = leaving_cores.iter().find(|lc| **lc == *core) {
                    Some(assigned_core_transcript(*core))
                } else {
                    None
                }
            },
        )
    };

    if let Some((vrf_in_out, vrf_proof, _)) = maybe_assignment {
        // Sanity: `core` is always initialized to non-default here, as the closure above
        // has been executed.
        *core_out = core;
        cert_output.data = *vrf_in_out.as_output_bytes();
        cert_proof.data = vrf_proof.to_bytes();
        true
    } else {
        false
    }
}

/// Makes verification with the given VRF proof and output and calculates tranche value
/// @param public_key_ptr byte representation of the public key that was used to sign the message
/// @param output_ptr the signature
/// @param proof_ptr the proof of the signature
/// @param n_delay_tranches - the number of delay tranches in total.
/// @param zeroth_delay_tranche_width - the zeroth delay tranche width.
/// @param relay_vrf_story - relay vrf story
/// @param core_index - leaving core for computing
/// @param tranche_out - output tranche
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_verify_and_get_tranche(
    public_key_ptr: *const u8,
    output_ptr: *const u8,
    proof_ptr: *const u8,
    n_delay_tranches: u32,
    zeroth_delay_tranche_width: u32,
    relay_vrf_story: *const RelayVRFStory,
    core_index: u32,
    tranche_out: *mut u32,
) -> Sr25519SignatureResult {
    assert!(!public_key_ptr.is_null());
    assert!(!output_ptr.is_null());
    assert!(!proof_ptr.is_null());
    assert!(!relay_vrf_story.is_null());
    assert!(!tranche_out.is_null());

    let public_key = create_public(slice::from_raw_parts(
        public_key_ptr,
        SR25519_PUBLIC_SIZE as usize,
    ));

    let tranche_out = tranche_out.as_mut().unwrap();
    let relay_vrf_story =
        std::mem::transmute::<*const RelayVRFStory, &RelayVRFStory>(relay_vrf_story);

    let transcript = relay_vrf_delay_transcript(relay_vrf_story.clone(), core_index);
    let (vrf_in_out, _) = return_if_err!(vrf_verify_transcript(
        public_key, transcript, output_ptr, proof_ptr
    ));
    *tranche_out =
        relay_vrf_delay_tranche(&vrf_in_out, n_delay_tranches, zeroth_delay_tranche_width);
    Sr25519SignatureResult::Ok
}

/// Computes output and proof for valid VRF delayed assignment certificate and tranche.
/// @param keypair_ptr - byte repr of valid keypair for signing
/// @param n_delay_tranches - the number of delay tranches in total.
/// @param zeroth_delay_tranche_width - the zeroth delay tranche width.
/// @param core - leaving core for computing
/// @param cert_output - certificate output
/// @param cert_proof - certificate proof
/// @param tranche_out - output tranche
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_relay_vrf_delay_assignments_cert(
    keypair_ptr: *const u8,
    n_delay_tranches: u32,
    zeroth_delay_tranche_width: u32,
    relay_vrf_story: *const RelayVRFStory,
    core: u32,
    cert_output: *mut VRFCOutput,
    cert_proof: *mut VRFCProof,
    tranche_out: *mut u32,
) {
    assert!(!cert_output.is_null());
    assert!(!cert_proof.is_null());
    assert!(!tranche_out.is_null());

    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let assignments_key = create_from_pair(keypair_bytes);

    let relay_vrf_story =
        std::mem::transmute::<*const RelayVRFStory, &RelayVRFStory>(relay_vrf_story);

    let cert_output = std::mem::transmute::<*mut VRFCOutput, &mut VRFCOutput>(cert_output);
    let cert_proof = std::mem::transmute::<*mut VRFCProof, &mut VRFCProof>(cert_proof);
    let tranche_out = tranche_out.as_mut().unwrap();

    let (vrf_in_out, vrf_proof, _) =
        assignments_key.vrf_sign(relay_vrf_delay_transcript(relay_vrf_story.clone(), core));

    let tranche =
        relay_vrf_delay_tranche(&vrf_in_out, n_delay_tranches, zeroth_delay_tranche_width);

    cert_output.data = *vrf_in_out.as_output_bytes();
    cert_proof.data = vrf_proof.to_bytes();
    *tranche_out = tranche;
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_vrf_verify_extra(
    keypair_ptr: *const u8,
    vrf_pre_output: *const u8,
    vrf_proof: *const u8,
    modulo_transcript_data: *const Strobe128,
    transcript_data: *const Strobe128
) -> VrfResultExtra {
    let keypair_bytes = slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE as usize);
    let keypair = create_from_pair(keypair_bytes);

    let vrf_pre_output = slice::from_raw_parts(vrf_pre_output, SR25519_VRF_OUTPUT_SIZE as usize);
    let vrf_pre_output = VRFOutput::from_bytes(vrf_pre_output).unwrap();

    let vrf_proof = slice::from_raw_parts(vrf_proof, SR25519_VRF_PROOF_SIZE as usize);
    let vrf_proof = VRFProof::from_bytes(vrf_proof).unwrap();

    let modulo_transcript = std::mem::transmute::<*const Strobe128, &mut Transcript>(modulo_transcript_data);
    let transcript = std::mem::transmute::<*const Strobe128, &mut Transcript>(transcript_data);

    let (in_out, proof) = return_if_err!(keypair.public.vrf_verify_extra(
        modulo_transcript,
        &vrf_pre_output,
        &vrf_proof,
        transcript
    ));

    VrfResultExtra {
        result: Sr25519SignatureResult::Ok,
        input_bytes: in_out.input.to_bytes(),
        output_bytes: in_out.output.to_bytes(),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use hex_literal::hex;
    use schnorrkel::{KEYPAIR_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

    fn generate_random_seed() -> Vec<u8> {
        (0..32).map(|_| rand::random::<u8>()).collect()
    }

    #[test]
    fn can_create_keypair() {
        let seed = generate_random_seed();
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };

        assert_eq!(keypair.len(), KEYPAIR_LENGTH);
    }

    #[test]
    fn creates_pair_from_known() {
        let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
        let expected = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        assert_eq!(public, expected);
    }

    #[test]
    fn can_sign_message() {
        let seed = generate_random_seed();
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let private = &keypair[0..SECRET_KEY_LENGTH];
        let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
        let message = b"this is a message";

        let mut signature = [0u8; SR25519_SIGNATURE_SIZE as usize];
        unsafe {
            sr25519_sign(
                signature.as_mut_ptr(),
                public.as_ptr(),
                private.as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
            )
        };

        assert_eq!(signature.len(), SIGNATURE_LENGTH);
    }

    #[test]
    fn can_verify_message() {
        let seed = generate_random_seed();
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let private = &keypair[0..SECRET_KEY_LENGTH];
        let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
        let message = b"this is a message";
        let mut signature = [0u8; SR25519_SIGNATURE_SIZE as usize];
        unsafe {
            sr25519_sign(
                signature.as_mut_ptr(),
                public.as_ptr(),
                private.as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
            )
        };
        let is_valid = unsafe {
            sr25519_verify(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
                public.as_ptr(),
            )
        };

        assert!(is_valid);
    }

    #[test]
    fn soft_derives_pair() {
        let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
        let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
        let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        let mut derived = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        unsafe { sr25519_derive_keypair_soft(derived.as_mut_ptr(), keypair.as_ptr(), cc.as_ptr()) };
        let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        assert_eq!(public, expected);
    }

    #[test]
    fn soft_derives_public() {
        let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
        let public = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
        let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
        let mut derived = [0u8; SR25519_PUBLIC_SIZE as usize];
        unsafe { sr25519_derive_public_soft(derived.as_mut_ptr(), public.as_ptr(), cc.as_ptr()) };

        assert_eq!(derived, expected);
    }

    #[test]
    fn hard_derives_pair() {
        let cc = hex!("14416c6963650000000000000000000000000000000000000000000000000000"); // Alice
        let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
        let expected = hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
        let mut keypair = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
        let mut derived = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_derive_keypair_hard(derived.as_mut_ptr(), keypair.as_ptr(), cc.as_ptr()) };
        let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        assert_eq!(public, expected);
    }

    fn make_test_keypair() -> Keypair {
        let seed = generate_random_seed();
        let mut keypair_bytes = [0u8; SR25519_KEYPAIR_SIZE as usize];
        unsafe { sr25519_keypair_from_seed(keypair_bytes.as_mut_ptr(), seed.as_ptr()) };
        let private = &keypair_bytes[0..SECRET_KEY_LENGTH];
        let public = &keypair_bytes[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

        Keypair::from_bytes(&keypair_bytes).expect("Keypair creation error")
    }

    #[test]
    fn vrf_verify() {
        let keypair = make_test_keypair();
        let message = b"Hello, world!";

        let ctx = signing_context(SIGNING_CTX).bytes(message);
        let (io, proof, _) = keypair.vrf_sign(ctx.clone());
        let (io_, proof_) = keypair
            .public
            .vrf_verify(ctx.clone(), &io.to_output(), &proof)
            .expect("Verification error");
        assert_eq!(io_, io);
        let decomp_proof = proof_
            .shorten_vrf(&keypair.public, ctx.clone(), &io.to_output())
            .expect("Shorten VRF");
        assert_eq!(proof, decomp_proof);
        unsafe {
            let threshold_bytes = [0u8; SR25519_VRF_THRESHOLD_SIZE as usize];
            let res = sr25519_vrf_verify(
                keypair.public.as_ref().as_ptr(),
                message.as_ptr(),
                message.len() as c_ulong,
                io.as_output_bytes().as_ptr(),
                proof.to_bytes().as_ptr(),
                threshold_bytes.as_ptr(),
            );
            assert_eq!(res.result, Sr25519SignatureResult::Ok);
        }
    }

    #[test]
    fn vrf_verify_transcript() {
        let keypair = make_test_keypair();
        let message = b"Hello, world!";

        let mut ctx = signing_context(SIGNING_CTX).bytes(message);
        let (io, proof, _) = keypair.vrf_sign(ctx.clone());
        let (io_, proof_) = keypair
            .public
            .vrf_verify(ctx.clone(), &io.to_output(), &proof)
            .expect("Verification error");
        assert_eq!(io_, io);
        let decomp_proof = proof_
            .shorten_vrf(&keypair.public, ctx.clone(), &io.to_output())
            .expect("Shorten VRF");
        assert_eq!(proof, decomp_proof);
        unsafe {
            let threshold_bytes = [0u8; SR25519_VRF_THRESHOLD_SIZE as usize];
            let res = sr25519_vrf_verify_transcript(
                keypair.public.as_ref().as_ptr(),
                std::mem::transmute::<&mut Transcript, *const Strobe128>(&mut ctx),
                io.as_output_bytes().as_ptr(),
                proof.to_bytes().as_ptr(),
                threshold_bytes.as_ptr(),
            );
            assert_eq!(res.result, Sr25519SignatureResult::Ok);
        }
    }
}
