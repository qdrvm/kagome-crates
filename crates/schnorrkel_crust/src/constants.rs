use std::os::raw::c_ulong;

/// Length of a random generator seed
pub const ED25519_SEED_LENGTH: c_ulong = 32;

/// The length of an ed25519 `PublicKey`, in bytes.
pub const ED25519_PUBLIC_KEY_LENGTH: c_ulong = 32;

/// The length of a ed25519 `SecretKey`, in bytes.
pub const ED25519_SECRET_KEY_LENGTH: c_ulong = 32;

/// The length of an ed25519 `Keypair`, in bytes.
pub const ED25519_KEYPAIR_LENGTH: c_ulong = ED25519_PUBLIC_KEY_LENGTH + ED25519_SECRET_KEY_LENGTH;

/// The length of a ed25519 `Signature`, in bytes.
pub const ED25519_SIGNATURE_LENGTH: c_ulong = 64;

/// The length of an "expanded" ed25519 key, `ExpandedSecretKey`, in bytes.
pub const ED25519_EXPANDED_SECRET_KEY_LENGTH: c_ulong = 64;

/// Size of input SEED for derivation, bytes
pub const SR25519_SEED_SIZE: c_ulong = 32;

/// Size of CHAINCODE, bytes
pub const SR25519_CHAINCODE_SIZE: c_ulong = 32;

/// Size of SR25519 PUBLIC KEY, bytes
pub const SR25519_PUBLIC_SIZE: c_ulong = 32;

/// Size of SR25519 PRIVATE (SECRET) KEY, which consists of [32 bytes key | 32 bytes nonce]
pub const SR25519_SECRET_SIZE: c_ulong = 64;

/// Size of SR25519 SIGNATURE, bytes
pub const SR25519_SIGNATURE_SIZE: c_ulong = 64;

/// Size of SR25519 KEYPAIR. [32 bytes key | 32 bytes nonce | 32 bytes public]
pub const SR25519_KEYPAIR_SIZE: c_ulong = 96;

/// Size of VRF output, bytes
pub const SR25519_VRF_OUTPUT_SIZE: usize = 32;

/// Size of VRF proof, bytes
pub const SR25519_VRF_PROOF_SIZE: usize = 64;

/// Size of VRF raw output, bytes
pub const SR25519_VRF_RAW_OUTPUT_SIZE: c_ulong = 16;

/// Size of VRF limit, bytes
pub const SR25519_VRF_THRESHOLD_SIZE: c_ulong = 16;

/// Size of VRF Story limit size
pub const RELAY_VRF_STORY_SIZE: usize = 32;

/// A hard upper bound on num_cores * target_checkers / num_validators
pub const MAX_MODULO_SAMPLES: usize = 40;

/// A static context used to compute the Relay VRF story based on the
/// VRF output included in the header-chain.
pub const RELAY_VRF_STORY_CONTEXT: &[u8] = b"A&V RC-VRF";

/// A static context used for all relay-vrf-modulo VRFs.
pub const RELAY_VRF_MODULO_CONTEXT: &[u8] = b"A&V MOD";

/// A static context associated with producing randomness for a core.
pub const CORE_RANDOMNESS_CONTEXT: &[u8] = b"A&V CORE";

/// A static context used for transcripts indicating assigned availability core.
pub const ASSIGNED_CORE_CONTEXT: &[u8] = b"A&V ASSIGNED";

/// A static context used for all relay-vrf-modulo VRFs.
pub const RELAY_VRF_DELAY_CONTEXT: &[u8] = b"A&V DELAY";

/// A static context associated with producing randomness for a tranche.
pub const TRANCHE_RANDOMNESS_CONTEXT: &[u8] = b"A&V TRANCHE";

/// A static context associated with producing randomness for a core.
pub const CORE_RANDOMNESS_CONTEXT_V2: &[u8] = b"A&V CORE v2";

/// A static context associated with producing randomness for v2 multi-core assignments.
pub const ASSIGNED_CORE_CONTEXT_V2: &[u8] = b"A&V ASSIGNED v2";

/// A static context used for all relay-vrf-modulo VRFs for v2 multi-core assignments.
pub const RELAY_VRF_MODULO_CONTEXT_V2: &[u8] = b"A&V MOD v2";
