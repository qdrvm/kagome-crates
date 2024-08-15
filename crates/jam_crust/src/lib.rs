use ark_ec_vrfs::prelude::ark_serialize::CanonicalDeserialize;
use ark_ec_vrfs::prelude::ark_serialize::CanonicalSerialize;
use ark_ec_vrfs::ring::Verifier;
use ark_ec_vrfs::suites::bandersnatch::edwards as bandersnatch;
use bandersnatch::PcsParams;
use bandersnatch::RingCommitment;
use bandersnatch::RingContext;
use bandersnatch::RingVerifier;
use cpp::Opaque;
use std::sync::OnceLock;

pub const JAM_BANDERSNATCH_OUTPUT: usize = 32;
pub const JAM_BANDERSNATCH_PUBLIC: usize = 32;
pub const JAM_BANDERSNATCH_RING_COMMITMENT: usize = 144;
pub const JAM_BANDERSNATCH_RING_SIGNATURE: usize = 784;

fn pcs_params() -> &'static PcsParams {
    static PCS_PARAMS: OnceLock<PcsParams> = OnceLock::new();
    PCS_PARAMS.get_or_init(|| {
        let raw = include_bytes!("../zcash-srs-2-11-compressed.bin");
        PcsParams::deserialize_compressed(&mut &raw[..]).unwrap()
    })
}

fn hashed_output(output: &bandersnatch::Output, output_out: &mut [u8]) {
    output_out.copy_from_slice(&output.hash()[..JAM_BANDERSNATCH_OUTPUT]);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_bandersnatch_output(
    signature: *const u8,
    output_out: *mut u8,
) -> bool {
    let signature = cpp::from_raw_parts(signature, 32);
    let output_out = cpp::from_raw_parts_mut(output_out, JAM_BANDERSNATCH_OUTPUT);
    let output =
        if let Ok(output) = bandersnatch::Output::deserialize_compressed(&mut &signature[..]) {
            output
        } else {
            return false;
        };
    hashed_output(&output, output_out);
    true
}

pub struct JamBandersnatchRing;
impl Opaque for JamBandersnatchRing {
    type Type = RingContext;
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_bandersnatch_ring_new(ring_size: u32) -> *mut JamBandersnatchRing {
    let ring_ctx = if let Ok(ring_ctx) = RingContext::from_srs(ring_size as _, pcs_params().clone())
    {
        ring_ctx
    } else {
        return Opaque::null();
    };
    Opaque::leak(ring_ctx)
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_bandersnatch_ring_drop(ring_ctx: *mut JamBandersnatchRing) {
    Opaque::drop(ring_ctx)
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_bandersnatch_ring_commitment(
    ring_ctx: *mut JamBandersnatchRing,
    public_keys: *const u8,
    public_keys_len: usize,
    ring_commitment_out: *mut u8,
) {
    let ring_ctx = Opaque::arg(ring_ctx);
    let public_keys = cpp::from_raw_parts(public_keys, public_keys_len);
    let ring_commitment_out =
        cpp::from_raw_parts_mut(ring_commitment_out, JAM_BANDERSNATCH_RING_COMMITMENT);
    let points: Vec<_> = public_keys
        .chunks(JAM_BANDERSNATCH_PUBLIC)
        .map(|pk| {
            if let Ok(pk) = bandersnatch::Public::deserialize_compressed(&mut &pk[..]) {
                pk.0
            } else {
                ring_ctx.padding_point()
            }
        })
        .collect();
    ring_ctx
        .verifier_key(&points)
        .commitment()
        .serialize_compressed(&mut &mut ring_commitment_out[..])
        .unwrap();
}

pub struct JamBandersnatchRingVerifier;
impl Opaque for JamBandersnatchRingVerifier {
    type Type = RingVerifier;
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_bandersnatch_ring_verifier_new(
    ring_ctx: *mut JamBandersnatchRing,
    ring_commitment: *const u8,
) -> *mut JamBandersnatchRingVerifier {
    let ring_ctx = Opaque::arg(ring_ctx);
    let ring_commitment = cpp::from_raw_parts(ring_commitment, JAM_BANDERSNATCH_RING_COMMITMENT);
    let ring_commitment = if let Ok(ring_commitment) =
        RingCommitment::deserialize_compressed(&mut &ring_commitment[..])
    {
        ring_commitment
    } else {
        return Opaque::null();
    };
    let verifier_key = ring_ctx.verifier_key_from_commitment(ring_commitment);
    let verifier = ring_ctx.verifier(verifier_key);
    Opaque::leak(verifier)
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_bandersnatch_ring_verifier_drop(
    verifier: *mut JamBandersnatchRingVerifier,
) {
    Opaque::drop(verifier)
}

type RingVrfSignature = (bandersnatch::Output, bandersnatch::RingProof);

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_bandersnatch_ring_verifier_verify(
    verifier: *mut JamBandersnatchRingVerifier,
    input: *const u8,
    input_len: usize,
    ring_signature: *const u8,
    output_out: *mut u8,
) -> bool {
    let verifier = Opaque::arg(verifier);
    let input = cpp::from_raw_parts(input, input_len);
    let ring_signature = cpp::from_raw_parts(ring_signature, JAM_BANDERSNATCH_RING_SIGNATURE);
    let output_out = cpp::from_raw_parts_mut(output_out, JAM_BANDERSNATCH_OUTPUT);
    let input = bandersnatch::Input::new(input).unwrap();
    let (output, ring_proof) = if let Ok(ring_signature) =
        RingVrfSignature::deserialize_compressed(&mut &ring_signature[..])
    {
        ring_signature
    } else {
        return false;
    };
    if bandersnatch::Public::verify(input, output, &[], &ring_proof, &verifier).is_err() {
        return false;
    }
    hashed_output(&output, output_out);
    true
}
