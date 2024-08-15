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

pub const JAM_VRF_OUTPUT: usize = 32;
pub const JAM_RING_COMMITMENT: usize = 144;
pub const JAM_RING_SIGNATURE: usize = 784;

fn pcs_params() -> &'static PcsParams {
    static PCS_PARAMS: OnceLock<PcsParams> = OnceLock::new();
    PCS_PARAMS.get_or_init(|| {
        let raw = include_bytes!("../zcash-srs-2-11-compressed.bin");
        PcsParams::deserialize_compressed(&mut &raw[..]).unwrap()
    })
}

fn hashed_output(output: &bandersnatch::Output, output_out: &mut [u8]) {
    output_out.copy_from_slice(&output.hash()[..JAM_VRF_OUTPUT]);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_vrf_output(signature: *const u8, output_out: *mut u8) -> bool {
    let signature = cpp::from_raw_parts(signature, 32);
    let output_out = cpp::from_raw_parts_mut(output_out, JAM_VRF_OUTPUT);
    let output =
        if let Ok(output) = bandersnatch::Output::deserialize_compressed(&mut &signature[..]) {
            output
        } else {
            return false;
        };
    hashed_output(&output, output_out);
    true
}

pub struct JamRing;
impl Opaque for JamRing {
    type Type = RingContext;
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_ring_new(ring_size: u32) -> *mut JamRing {
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
pub unsafe extern "C" fn jam_ring_drop(ring_ctx: *mut JamRing) {
    Opaque::drop(ring_ctx)
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_ring_commitment(
    ring_ctx: *mut JamRing,
    public_keys: *const u8,
    public_keys_len: usize,
    ring_commitment_out: *mut u8,
) -> bool {
    const PK_LEN: usize = 32;
    let ring_ctx = Opaque::arg(ring_ctx);
    let public_keys = cpp::from_raw_parts(public_keys, public_keys_len);
    let ring_commitment_out = cpp::from_raw_parts_mut(ring_commitment_out, JAM_RING_COMMITMENT);
    let mut points = vec![];
    for key in public_keys.chunks(PK_LEN) {
        let pk = if let Ok(pk) = bandersnatch::Public::deserialize_compressed(&mut &key[..]) {
            pk
        } else {
            return false;
        };
        points.push(pk.0);
    }
    ring_ctx
        .verifier_key(&points)
        .commitment()
        .serialize_compressed(&mut &mut ring_commitment_out[..])
        .unwrap();
    true
}

pub struct JamRingVerifier;
impl Opaque for JamRingVerifier {
    type Type = RingVerifier;
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_ring_verifier_new(
    ring_ctx: *mut JamRing,
    ring_commitment: *const u8,
) -> *mut JamRingVerifier {
    let ring_ctx = Opaque::arg(ring_ctx);
    let ring_commitment = cpp::from_raw_parts(ring_commitment, JAM_RING_COMMITMENT);
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
pub unsafe extern "C" fn jam_ring_verifier_drop(verifier: *mut JamRingVerifier) {
    Opaque::drop(verifier)
}

type RingVrfSignature = (bandersnatch::Output, bandersnatch::RingProof);

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn jam_ring_verifier_verify(
    verifier: *mut JamRingVerifier,
    input: *const u8,
    input_len: usize,
    ring_signature: *const u8,
    output_out: *mut u8,
) -> bool {
    let verifier = Opaque::arg(verifier);
    let input = cpp::from_raw_parts(input, input_len);
    let ring_signature = cpp::from_raw_parts(ring_signature, JAM_RING_SIGNATURE);
    let output_out = cpp::from_raw_parts_mut(output_out, JAM_VRF_OUTPUT);
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
