use cpp::from_raw_parts;
use cpp::from_raw_parts_mut;
use cpp::Opaque;
use ssz::{Decode, Encode};
use std::ops::Range;
use std::os::raw::{c_char, c_int, c_uchar};
use std::sync::Once;

// Production config (default)
mod config {
    pub use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::{
        PubKeyAbortingTargetSumLifetime32Dim46Base8 as XmssPublicKey,
        SchemeAbortingTargetSumLifetime32Dim46Base8 as XmssScheme,
        SecretKeyAbortingTargetSumLifetime32Dim46Base8 as XmssSecretKey,
        SigAbortingTargetSumLifetime32Dim46Base8 as XmssSignature,
    };
    pub const PQ_SIGNATURE_SIZE: usize = 2536;
}

pub use config::PQ_SIGNATURE_SIZE;
use config::*;

use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use leansig::signature::SignatureSchemeSecretKey;
use leansig::MESSAGE_LENGTH;

pub const PQ_PUBLIC_KEY_SIZE: usize = 52;
pub const PQ_MESSAGE_SIZE: usize = 32; // cbindgen bug, MESSAGE_LENGTH

/// Opaque type for secret key
pub struct PQSecretKey;
impl Opaque for PQSecretKey {
    type Type = XmssSecretKey;
}

/// Opaque type for public key
pub struct PQPublicKey;
impl Opaque for PQPublicKey {
    type Type = XmssPublicKey;
}

/// Opaque type for signature
pub struct PQSignature;
impl Opaque for PQSignature {
    type Type = XmssSignature;
}

/// Range representation for C
#[repr(C)]
pub struct PQRange {
    pub start: u64,
    pub end: u64,
}

impl From<Range<u64>> for PQRange {
    fn from(range: Range<u64>) -> Self {
        PQRange {
            start: range.start,
            end: range.end,
        }
    }
}

/// Error codes for signature scheme
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum PQSigningError {
    /// Success (not an error)
    Success = 0,
    /// Failed to encode message after maximum number of attempts
    EncodingAttemptsExceeded = 1,
    /// Invalid pointer (null pointer)
    InvalidPointer = 2,
    /// Unknown error
    UnknownError = 99,
}

/// Owned byte vector.
/// Deallocated with `PQByteVec_drop`.
#[repr(C)]
pub struct PQByteVec {
    pub ptr: *mut c_uchar,
    pub size: usize,
}
impl PQByteVec {
    /// Allocate byte vector and copy bytes from slice.
    fn new(bytes: &[u8]) -> Self {
        let mut vec = bytes.to_vec();
        assert_eq!(vec.capacity(), vec.len());
        let ptr = vec.as_mut_ptr();
        std::mem::forget(vec);
        Self {
            ptr,
            size: bytes.len(),
        }
    }
}

/// Destroy `PQByteVec`.
#[no_mangle]
pub unsafe extern "C" fn PQByteVec_drop(bytes: PQByteVec) {
    drop(Vec::from_raw_parts(bytes.ptr, bytes.size, bytes.size))
}

#[repr(C)]
pub struct PQChildProof {
    pub proof_ptr: *const c_uchar,
    pub proof_size: usize,
    pub public_keys_bytes_ptr: *const *const c_uchar,
    pub public_keys_count: usize,
}

static PROVER_INIT: Once = Once::new();
static VERIFIER_INIT: Once = Once::new();

#[no_mangle]
pub extern "C" fn pq_setup_prover() {
    PROVER_INIT.call_once(|| {
        rec_aggregation::init_aggregation_bytecode();
        backend::precompute_dft_twiddles::<backend::KoalaBear>(1 << 24);
    });
}

/// Initialize the verifier (idempotent - only runs once)
/// This is safe to call multiple times; setup only happens on first call.
#[no_mangle]
pub extern "C" fn pq_setup_verifier() {
    VERIFIER_INIT.call_once(|| {
        rec_aggregation::init_aggregation_bytecode();
    });
}

/// Convert message from byte slice to byte array.
unsafe fn get_message(message: *const u8) -> [u8; MESSAGE_LENGTH] {
    from_raw_parts(message, MESSAGE_LENGTH).try_into().unwrap()
}

/// Encode value to json.
fn to_json<T: Serializable>(value: &T) -> PQByteVec {
    let json = serde_json::to_string(value).unwrap();
    PQByteVec::new(json.as_ref())
}

/// Decode value from json.
unsafe fn from_json<T: Opaque<Type = impl Serializable>>(
    json_ptr: *const c_uchar,
    json_size: usize,
    value_out: *mut *mut T,
) -> PQSigningError {
    if json_ptr.is_null() || value_out.is_null() {
        return PQSigningError::InvalidPointer;
    }
    let json = from_raw_parts(json_ptr, json_size);
    let Ok(value) = serde_json::from_slice::<T::Type>(json) else {
        return PQSigningError::UnknownError;
    };
    *value_out = Opaque::leak(value);
    PQSigningError::Success
}

/// Encode value to bytes.
unsafe fn to_bytes<T: Serializable>(value: &T, bytes_out: &mut [u8]) {
    let bytes = value.to_bytes();
    assert_eq!(bytes.len(), bytes_out.len());
    bytes_out.copy_from_slice(&bytes);
}

/// Decode value from bytes.
unsafe fn from_bytes<T: Opaque<Type = impl Serializable>>(
    bytes: &[u8],
    value_out: *mut *mut T,
) -> PQSigningError {
    if value_out.is_null() {
        return PQSigningError::InvalidPointer;
    }
    let Ok(value) = T::Type::from_bytes(bytes) else {
        return PQSigningError::UnknownError;
    };
    *value_out = Opaque::leak(value);
    PQSigningError::Success
}

unsafe fn many_from_bytes<T: Serializable>(
    ptr: *const *const u8,
    count: usize,
    item_size: usize,
) -> Option<Vec<T>> {
    from_raw_parts(ptr, count)
        .into_iter()
        .map(|ptr| T::from_bytes(from_raw_parts(*ptr, item_size)).ok())
        .collect()
}

// ============================================================================
// Memory management functions
// ============================================================================

/// Frees memory allocated for secret key
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_free(secret_key: *mut PQSecretKey) {
    if secret_key.is_null() {
        return;
    }
    Opaque::drop(secret_key);
}

/// Frees memory allocated for public key
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_free(public_key: *mut PQPublicKey) {
    if public_key.is_null() {
        return;
    }
    Opaque::drop(public_key);
}

/// Frees memory allocated for signature
#[no_mangle]
pub unsafe extern "C" fn pq_signature_free(signature: *mut PQSignature) {
    if signature.is_null() {
        return;
    }
    Opaque::drop(signature);
}

// ============================================================================
// SignatureSchemeSecretKey functions
// ============================================================================

/// Get key activation interval
#[no_mangle]
pub unsafe extern "C" fn pq_get_activation_interval(secret_key: *const PQSecretKey) -> PQRange {
    if secret_key.is_null() {
        return PQRange { start: 0, end: 0 };
    }
    let secret_key = Opaque::arg(secret_key);
    secret_key.get_activation_interval().into()
}

/// Get prepared interval of the key
#[no_mangle]
pub unsafe extern "C" fn pq_get_prepared_interval(secret_key: *const PQSecretKey) -> PQRange {
    if secret_key.is_null() {
        return PQRange { start: 0, end: 0 };
    }
    let secret_key = Opaque::arg(secret_key);
    secret_key.get_prepared_interval().into()
}

/// Advance key preparation to next interval
#[no_mangle]
pub unsafe extern "C" fn pq_advance_preparation(secret_key: *mut PQSecretKey) {
    if secret_key.is_null() {
        return;
    }
    let secret_key = Opaque::arg_mut(secret_key);
    secret_key.advance_preparation();
}

// ============================================================================
// SignatureScheme functions
// ============================================================================

/// Get maximum lifetime of signature scheme
#[no_mangle]
pub extern "C" fn pq_get_lifetime() -> u64 {
    XmssScheme::LIFETIME
}

/// Generate key pair (public and secret)
///
/// # Parameters
/// - `activation_epoch`: starting epoch for key activation
/// - `num_active_epochs`: number of active epochs
/// - `public_key_out`: pointer to write public key (output)
/// - `secret_key_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code (Success = 0 on success)
///
/// # Safety
/// Pointers public_key_out and secret_key_out must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_key_gen(
    activation_epoch: usize,
    num_active_epochs: usize,
    public_key_out: *mut *mut PQPublicKey,
    secret_key_out: *mut *mut PQSecretKey,
) -> PQSigningError {
    if public_key_out.is_null() || secret_key_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let mut rng = rand::rng();
    let (public_key, secret_key) =
        XmssScheme::key_gen(&mut rng, activation_epoch, num_active_epochs);
    let public_key = XmssPublicKey::from_bytes(&public_key.to_bytes()).unwrap();
    *public_key_out = Opaque::leak(public_key);
    *secret_key_out = Opaque::leak(secret_key);
    PQSigningError::Success
}

/// Sign a message
///
/// # Parameters
/// - `secret_key`: secret key for signing
/// - `epoch`: epoch for which signature is created
/// - `message`: pointer to message
/// - `signature_out`: pointer to write signature (output)
///
/// # Returns
/// Error code (Success = 0 on success)
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_sign(
    secret_key: *const PQSecretKey,
    epoch: u32,
    message: *const u8,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if secret_key.is_null() || message.is_null() || signature_out.is_null() {
        return PQSigningError::InvalidPointer;
    }
    let secret_key = Opaque::arg(secret_key);
    let message = get_message(message);
    match XmssScheme::sign(&secret_key, epoch, &message) {
        Ok(signature) => {
            let signature = XmssSignature::from_ssz_bytes(&signature.as_ssz_bytes()).unwrap();
            *signature_out = Opaque::leak(signature);
            PQSigningError::Success
        }
        Err(leansig::signature::SigningError::EncodingAttemptsExceeded { .. }) => {
            PQSigningError::EncodingAttemptsExceeded
        }
    }
}

/// Verify a signature
///
/// # Parameters
/// - `public_key`: public key
/// - `epoch`: signature epoch
/// - `message`: pointer to message
/// - `signature`: signature to verify
///
/// # Returns
/// 1 if signature is valid, 0 if invalid, negative value on error
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_verify(
    public_key: *const PQPublicKey,
    epoch: u32,
    message: *const u8,
    signature: *const PQSignature,
) -> c_int {
    if public_key.is_null() || message.is_null() || signature.is_null() {
        return -1; // Error: invalid pointer
    }

    let public_key = Opaque::arg(public_key);
    let signature = Opaque::arg(signature);
    let message = get_message(message);

    let is_valid = XmssScheme::verify(&public_key, epoch, &message, &signature);

    if is_valid {
        1
    } else {
        0
    }
}

// ============================================================================
// Error handling functions
// ============================================================================

/// Get error description string
///
/// # Parameters
/// - `error`: error code
///
/// # Returns
/// Pointer to C-string with error description.
#[no_mangle]
pub extern "C" fn pq_error_description(error: PQSigningError) -> *const c_char {
    match error {
        PQSigningError::Success => c"Success",
        PQSigningError::EncodingAttemptsExceeded => {
            c"Failed to encode message after maximum number of attempts"
        }
        PQSigningError::InvalidPointer => c"Invalid pointer (null pointer passed)",
        _ => c"Unknown error",
    }
    .as_ptr()
}

// ============================================================================
// Serialization functions
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_to_bytes(secret_key: *const PQSecretKey) -> PQByteVec {
    let bytes = Opaque::arg(secret_key).as_ssz_bytes();
    PQByteVec::new(&bytes)
}

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_from_bytes(
    bytes_ptr: *const c_uchar,
    bytes_size: usize,
    secret_key_out: *mut *mut PQSecretKey,
) -> PQSigningError {
    from_bytes(from_raw_parts(bytes_ptr, bytes_size), secret_key_out)
}

/// Serialize public key to bytes
///
/// # Parameters
/// - `public_key`: public key
/// - `public_key_bytes_out`: buffer for writing
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_to_bytes(
    public_key: *const PQPublicKey,
    public_key_bytes_out: *mut u8,
) {
    to_bytes(
        Opaque::arg(public_key),
        from_raw_parts_mut(public_key_bytes_out, PQ_PUBLIC_KEY_SIZE),
    );
}

/// Deserialize public key from bytes
///
/// # Parameters
/// - `public_key_bytes`: buffer with data
/// - `public_key_out`: pointer to write public key (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_from_bytes(
    public_key_bytes: *const u8,
    public_key_out: *mut *mut PQPublicKey,
) -> PQSigningError {
    from_bytes(
        from_raw_parts(public_key_bytes, PQ_PUBLIC_KEY_SIZE),
        public_key_out,
    )
}

/// Serialize signature to bytes
///
/// # Parameters
/// - `signature`: signature
/// - `signature_bytes_out`: buffer for writing
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_signature_to_bytes(
    signature: *const PQSignature,
    signature_bytes_out: *mut u8,
) {
    to_bytes(
        Opaque::arg(signature),
        from_raw_parts_mut(signature_bytes_out, PQ_SIGNATURE_SIZE),
    );
}

/// Deserialize signature from bytes
///
/// # Parameters
/// - `signature_bytes`: buffer with data
/// - `signature_out`: pointer to write signature (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_signature_from_bytes(
    signature_bytes: *const u8,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    from_bytes(
        from_raw_parts(signature_bytes, PQ_SIGNATURE_SIZE),
        signature_out,
    )
}

// ============================================================================
// JSON deserialization functions
// ============================================================================

/// Deserialize public key from JSON string
///
/// # Parameters
/// - `json_ptr`: JSON string pointer
/// - `json_size`: JSON string size
/// - `public_key_out`: pointer to write public key (output)
///
/// # Returns
/// Error code
///
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_from_json(
    json_ptr: *const c_uchar,
    json_size: usize,
    public_key_out: *mut *mut PQPublicKey,
) -> PQSigningError {
    from_json(json_ptr, json_size, public_key_out)
}

/// Deserialize secret key from JSON string
///
/// # Parameters
/// - `json_ptr`: JSON string pointer
/// - `json_size`: JSON string size
/// - `secret_key_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code
///
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_from_json(
    json_ptr: *const c_uchar,
    json_size: usize,
    secret_key_out: *mut *mut PQSecretKey,
) -> PQSigningError {
    from_json(json_ptr, json_size, secret_key_out)
}

/// Encode secret key to json
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_to_json(secret_key: *const PQSecretKey) -> PQByteVec {
    to_json(Opaque::arg(secret_key))
}

/// Encode public key to json
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_to_json(public_key: *const PQPublicKey) -> PQByteVec {
    to_json(Opaque::arg(public_key))
}

#[no_mangle]
pub unsafe extern "C" fn pq_aggregate_signatures(
    children_ptr: *const PQChildProof,
    children_size: usize,
    signature_count: usize,
    public_keys_bytes_ptr: *const *const u8,
    signatures_bytes_ptr: *const *const u8,
    epoch: u32,
    message: *const u8,
    log_inv_rate: usize,
) -> PQByteVec {
    let children_public_keys: Vec<_> = from_raw_parts(children_ptr, children_size)
        .into_iter()
        .map(|child| {
            many_from_bytes::<XmssPublicKey>(
                child.public_keys_bytes_ptr,
                child.public_keys_count,
                PQ_PUBLIC_KEY_SIZE,
            )
            .unwrap()
        })
        .collect();
    let children_proofs: Vec<_> = from_raw_parts(children_ptr, children_size)
        .into_iter()
        .map(|child| {
            rec_aggregation::AggregatedXMSS::deserialize(from_raw_parts(
                child.proof_ptr,
                child.proof_size,
            ))
            .unwrap()
        })
        .collect();
    let public_keys = many_from_bytes::<XmssPublicKey>(
        public_keys_bytes_ptr,
        signature_count,
        PQ_PUBLIC_KEY_SIZE,
    )
    .unwrap();
    let signatures =
        many_from_bytes::<XmssSignature>(signatures_bytes_ptr, signature_count, PQ_SIGNATURE_SIZE)
            .unwrap();
    let message = get_message(message);
    let (_, aggregated_signature) = rec_aggregation::xmss_aggregate(
        &children_public_keys
            .iter()
            .map(|public_keys| &public_keys[..])
            .zip(children_proofs.into_iter())
            .collect::<Vec<_>>(),
        public_keys
            .into_iter()
            .zip(signatures.into_iter())
            .collect(),
        &message,
        epoch,
        log_inv_rate,
    );

    let aggregated_signature_bytes = aggregated_signature.serialize();

    PQByteVec::new(&aggregated_signature_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn pq_verify_aggregated_signatures(
    signature_count: usize,
    public_keys_bytes_ptr: *const *const u8,
    epoch: u32,
    message: *const u8,
    aggregated_signatures_ptr: *const u8,
    aggregated_signatures_size: usize,
) -> bool {
    let public_keys = many_from_bytes::<XmssPublicKey>(
        public_keys_bytes_ptr,
        signature_count,
        PQ_PUBLIC_KEY_SIZE,
    )
    .unwrap();
    let message = get_message(message);
    let aggregated_signature_bytes =
        from_raw_parts(aggregated_signatures_ptr, aggregated_signatures_size);

    let aggregated_signature =
        match rec_aggregation::AggregatedXMSS::deserialize(aggregated_signature_bytes) {
            Some(aggregated_signature) => aggregated_signature,
            _ => return false,
        };

    rec_aggregation::xmss_verify_aggregation(public_keys, &aggregated_signature, &message, epoch)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen_and_sign() {
        unsafe {
            let mut public_key = PQPublicKey::null();
            let mut secret_key = PQSecretKey::null();

            // Key generation
            let result = pq_key_gen(0, 200, &mut public_key, &mut secret_key);
            assert_eq!(result, PQSigningError::Success);
            assert!(!public_key.is_null());
            assert!(!secret_key.is_null());

            // Check intervals
            let activation = pq_get_activation_interval(secret_key);
            assert!(activation.start < activation.end);

            let prepared = pq_get_prepared_interval(secret_key);
            assert!(prepared.start < prepared.end);

            // Sign message
            let message = [0u8; MESSAGE_LENGTH];
            let mut signature = PQSignature::null();
            let sign_result = pq_sign(secret_key, 10, message.as_ptr(), &mut signature);
            assert_eq!(sign_result, PQSigningError::Success);
            assert!(!signature.is_null());

            // Verify signature
            let verify_result = pq_verify(public_key, 10, message.as_ptr(), signature);
            assert_eq!(verify_result, 1);

            // Cleanup
            pq_signature_free(signature);
            pq_public_key_free(public_key);
            pq_secret_key_free(secret_key);
        }
    }

    #[test]
    fn test_error_description() {
        let desc = pq_error_description(PQSigningError::Success);
        assert!(!desc.is_null());
    }

    #[test]
    fn test_invalid_pointers() {
        unsafe {
            // Test with null pointers
            let result = pq_key_gen(0, 1000, std::ptr::null_mut(), std::ptr::null_mut());
            assert_eq!(result, PQSigningError::InvalidPointer);

            let mut public_key = PQPublicKey::null();
            let result = pq_key_gen(0, 1000, &mut public_key, std::ptr::null_mut());
            assert_eq!(result, PQSigningError::InvalidPointer);

            // pq_sign with null pointers
            let message = [0u8; PQ_MESSAGE_SIZE];
            let result = pq_sign(std::ptr::null(), 0, message.as_ptr(), std::ptr::null_mut());
            assert_eq!(result, PQSigningError::InvalidPointer);

            // pq_verify with null pointers
            let verify_result = pq_verify(std::ptr::null(), 0, message.as_ptr(), std::ptr::null());
            assert_eq!(verify_result, -1);

            // Freeing null pointers should not panic
            pq_secret_key_free(std::ptr::null_mut());
            pq_public_key_free(std::ptr::null_mut());
            pq_signature_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn test_signature_verification_with_wrong_data() {
        unsafe {
            let mut public_key = PQPublicKey::null();
            let mut secret_key = PQSecretKey::null();
            pq_key_gen(0, 200, &mut public_key, &mut secret_key);

            let message = [1u8; PQ_MESSAGE_SIZE];
            let mut signature = PQSignature::null();
            pq_sign(secret_key, 10, message.as_ptr(), &mut signature);

            // Check with correct data
            let result = pq_verify(public_key, 10, message.as_ptr(), signature);
            assert_eq!(result, 1);

            // Check with wrong epoch
            let result = pq_verify(public_key, 11, message.as_ptr(), signature);
            assert_eq!(result, 0);

            // Check with modified message
            let wrong_message = [2u8; PQ_MESSAGE_SIZE];
            let result = pq_verify(public_key, 10, wrong_message.as_ptr(), signature);
            assert_eq!(result, 0);

            pq_signature_free(signature);
            pq_public_key_free(public_key);
            pq_secret_key_free(secret_key);
        }
    }

    #[test]
    fn test_advance_preparation() {
        unsafe {
            let mut public_key = PQPublicKey::null();
            let mut secret_key = PQSecretKey::null();
            pq_key_gen(0, 192, &mut public_key, &mut secret_key);

            let initial_prepared = pq_get_prepared_interval(secret_key);
            assert!(initial_prepared.start < initial_prepared.end);

            // Advance preparation
            pq_advance_preparation(secret_key);
            let new_prepared = pq_get_prepared_interval(secret_key);

            // New interval should be shifted
            assert!(new_prepared.start > initial_prepared.start);
            assert!(new_prepared.end > initial_prepared.end);

            // Advance again
            pq_advance_preparation(secret_key);
            let newer_prepared = pq_get_prepared_interval(secret_key);
            assert!(newer_prepared.start > new_prepared.start);

            pq_public_key_free(public_key);
            pq_secret_key_free(secret_key);
        }
    }

    #[test]
    fn test_serialization_deserialization() {
        unsafe {
            let mut public_key = PQPublicKey::null();
            let mut secret_key = PQSecretKey::null();
            pq_key_gen(0, 200, &mut public_key, &mut secret_key);

            let message = [42u8; PQ_MESSAGE_SIZE];
            let mut signature = PQSignature::null();
            pq_sign(secret_key, 10, message.as_ptr(), &mut signature);

            // Test public key serialization/deserialization
            let mut public_key_bytes = vec![0u8; PQ_PUBLIC_KEY_SIZE];
            pq_public_key_to_bytes(public_key, public_key_bytes.as_mut_ptr());

            let mut public_key_restored = PQPublicKey::null();
            let result =
                pq_public_key_from_bytes(public_key_bytes.as_ptr(), &mut public_key_restored);
            assert_eq!(result, PQSigningError::Success);
            assert!(!public_key_restored.is_null());

            // Check that restored key works
            let verify_result = pq_verify(public_key_restored, 10, message.as_ptr(), signature);
            assert_eq!(verify_result, 1);

            // Test secret key serialization/deserialization
            let secret_key_json = pq_secret_key_to_json(secret_key);
            let mut secret_key_restored = PQSecretKey::null();
            let result = pq_secret_key_from_json(
                secret_key_json.ptr,
                secret_key_json.size,
                &mut secret_key_restored,
            );
            assert_eq!(result, PQSigningError::Success);
            PQByteVec_drop(secret_key_json);
            assert!(!secret_key_restored.is_null());

            // Check that restored key can sign
            let mut new_signature = PQSignature::null();
            let result = pq_sign(
                secret_key_restored,
                20,
                message.as_ptr(),
                &mut new_signature,
            );
            assert_eq!(result, PQSigningError::Success);

            // Test signature serialization/deserialization
            let mut signature_bytes = vec![0u8; PQ_SIGNATURE_SIZE];
            pq_signature_to_bytes(signature, signature_bytes.as_mut_ptr());

            let mut signature_restored = PQSignature::null();
            let result = pq_signature_from_bytes(signature_bytes.as_ptr(), &mut signature_restored);
            assert_eq!(result, PQSigningError::Success);
            assert!(!signature_restored.is_null());

            // Check restored signature
            let verify_result = pq_verify(public_key, 10, message.as_ptr(), signature_restored);
            assert_eq!(verify_result, 1);

            // Cleanup
            pq_signature_free(signature_restored);
            pq_signature_free(new_signature);
            pq_signature_free(signature);
            pq_secret_key_free(secret_key_restored);
            pq_secret_key_free(secret_key);
            pq_public_key_free(public_key_restored);
            pq_public_key_free(public_key);
        }
    }

    #[test]
    fn test_multiple_signatures() {
        unsafe {
            let mut public_key = PQPublicKey::null();
            let mut secret_key = PQSecretKey::null();
            pq_key_gen(0, 200, &mut public_key, &mut secret_key);

            // Sign several different messages with different epochs
            for epoch in [5, 10, 15, 20, 25] {
                let message = [epoch as u8; PQ_MESSAGE_SIZE];
                let mut signature = PQSignature::null();

                let result = pq_sign(secret_key, epoch, message.as_ptr(), &mut signature);
                assert_eq!(result, PQSigningError::Success);

                let verify_result = pq_verify(public_key, epoch, message.as_ptr(), signature);
                assert_eq!(verify_result, 1);

                // Verification with wrong epoch should fail
                let wrong_verify = pq_verify(public_key, epoch + 1, message.as_ptr(), signature);
                assert_eq!(wrong_verify, 0);

                pq_signature_free(signature);
            }

            pq_public_key_free(public_key);
            pq_secret_key_free(secret_key);
        }
    }

    #[test]
    fn test_get_lifetime() {
        let lifetime = pq_get_lifetime();
        assert_eq!(lifetime, 256); // 2^8
    }

    #[test]
    fn test_activation_and_prepared_intervals() {
        unsafe {
            let activation_epoch = 0;
            let num_active_epochs = 200;

            let mut public_key = PQPublicKey::null();
            let mut secret_key = PQSecretKey::null();
            pq_key_gen(
                activation_epoch,
                num_active_epochs,
                &mut public_key,
                &mut secret_key,
            );

            let activation = pq_get_activation_interval(secret_key);
            let prepared = pq_get_prepared_interval(secret_key);

            // Activation interval should contain prepared interval
            assert!(activation.start <= prepared.start);
            assert!(activation.end >= prepared.end);

            // Check interval sizes
            let activation_size = activation.end - activation.start;
            let prepared_size = prepared.end - prepared.start;

            assert!(activation_size >= prepared_size);

            pq_public_key_free(public_key);
            pq_secret_key_free(secret_key);
        }
    }

    #[test]
    fn test_all_error_descriptions() {
        // Check all error variants
        let errors = vec![
            PQSigningError::Success,
            PQSigningError::EncodingAttemptsExceeded,
            PQSigningError::InvalidPointer,
            PQSigningError::UnknownError,
        ];

        for error in errors {
            let desc = pq_error_description(error);
            assert!(!desc.is_null());
            unsafe {
                let c_str = std::ffi::CStr::from_ptr(desc);
                let desc_str = c_str.to_str().unwrap();
                assert!(!desc_str.is_empty());
            }
        }
    }
}
