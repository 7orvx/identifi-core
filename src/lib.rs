use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, BigInteger};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize}; 
use ark_std::rand::{SeedableRng};
use ark_std::rand::rngs::StdRng;

pub type G1Projective = <Bn254 as Pairing>::G1;
pub type G2Projective = <Bn254 as Pairing>::G2; 
pub type Fr = <Bn254 as Pairing>::ScalarField;

use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_snark::SNARK;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;

// Unified Sponge/Poseidon Infrastructure v0.4.0
use ark_crypto_primitives::sponge::{
    CryptographicSponge,
    FieldBasedCryptographicSponge, // Essential to enable native squeeze
    poseidon::{PoseidonConfig, PoseidonSponge},
};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;

use wasm_bindgen::prelude::*;

// ==========================================
// HELPER: SECURE HEX PARSER (Uniquely Mapped)
// ==========================================
fn fr_from_hex(hex_str: &str) -> Result<Fr, String> {
    let clean_hex = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(clean_hex).map_err(|_| "ERR_HEX_DECODE".to_string())?;
    
    let mut padded_bytes = [0u8; 32];
    if bytes.len() <= 32 {
        padded_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
    } else {
        return Err("ERR_FIELD_OVERFLOW".to_string());
    }
    Ok(Fr::from_be_bytes_mod_order(&padded_bytes))
}

fn fr_from_hex_wasm(hex_str: &str) -> Result<Fr, JsValue> {
    fr_from_hex(hex_str).map_err(|e| JsValue::from_str(&e))
}

// Initialize stable Poseidon parameters for BN254 using fixed seed generator
fn get_poseidon_config() -> PoseidonConfig<Fr> {
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 5;

    // Instead of using dynamic property-based search that expands the state,
    // we use the fixed seed (hash-to-field) generator that guarantees exactly size 3
    let (ark, mds) = ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds::<Fr>(
        254, // prime_id_bits
        3,   // Force original base state_size of 3 elements
        full_rounds,
        partial_rounds,
        alpha,
    );

    // If find_poseidon above returned size 9 because of the previous loop, 
    // we will ensure that we are extracting only the exact slices for size 3,
    // or we use the standard constructor with the generated values if it accepts the real size.
    // To mitigate the rounding behavior of v0.4.0, we pass the size it generated:
    let real_width = mds.len(); 
    let real_capacity = real_width - 2; // width = rate (2) + capacity

    PoseidonConfig::<Fr>::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        2,             // Fixed rate of 2 for our circuit
        real_capacity, // Capacity dynamically adapted perfectly to what the library generated
    )
}

// Native Poseidon helper exported to WASM (Pure calculation in JS)
#[wasm_bindgen]
pub fn compute_poseidon_native(master_hex: &str, sub_hex: &str) -> Result<String, JsValue> {
    let a = fr_from_hex_wasm(master_hex)?;
    let b = fr_from_hex_wasm(sub_hex)?;

    let config = get_poseidon_config(); 
    let mut sponge = PoseidonSponge::new(&config);

    sponge.absorb(&a);
    sponge.absorb(&b);
    let output = sponge.squeeze_native_field_elements(1).get(0)
        .copied()
        .ok_or_else(|| JsValue::from_str("ERR_SQUEEZE_FAILED"))?;

    let big_int: <Fr as PrimeField>::BigInt = output.into();
    let be_bytes = big_int.to_bytes_be();
    Ok(format!("0x{}", hex::encode(be_bytes)))
}

// Unified Poseidon Expor utility to calculate deterministic added root (Legacy or compatibility)
#[wasm_bindgen]
pub fn compute_commitment_root_wasm(master_hex: &str, sub_hex: &str) -> Result<String, JsValue> {
    let master = fr_from_hex_wasm(master_hex)?;
    let sub = fr_from_hex_wasm(sub_hex)?;

    let root = master + sub;

    let big_int: <Fr as PrimeField>::BigInt = root.into();
    let be_bytes = big_int.to_bytes_be();
    Ok(format!("0x{}", hex::encode(be_bytes)))
}

// ==========================================
// 1. THE IDENTIFI v2.0 CIRCUIT (Updated with Merkle Tree Gadget)
// ==========================================
pub struct IdentiFIClusterCircuit {
    pub master_address: Option<Fr>,       // Private Witness
    pub sub_wallet_address: Option<Fr>,   // Private Witness
    pub commitment_root: Option<Fr>,      // Public Input
    pub timestamp_exp: Option<Fr>,        // Public Input
    pub timestamp_iat: Option<Fr>,        // Public Input
    
    // Elements for dynamic inclusion proof (Depth 4 = Up to 16 Wallets)
    pub path_elements: Vec<Option<Fr>>,   // Sibling hashes on the path (Size 4)
    pub path_indices: Vec<Option<bool>>,  // false if sibling is on the left, true if on the right (Size 4)
}

impl ConstraintSynthesizer<Fr> for IdentiFIClusterCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocation of Public Inputs
        let root_var = FpVar::new_input(cs.clone(), || self.commitment_root.ok_or(SynthesisError::AssignmentMissing))?;
        let exp_var = FpVar::new_input(cs.clone(), || self.timestamp_exp.ok_or(SynthesisError::AssignmentMissing))?;
        let iat_var = FpVar::new_input(cs.clone(), || self.timestamp_iat.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocation of Private Inputs (Witness)
        let master_var = FpVar::new_witness(cs.clone(), || self.master_address.ok_or(SynthesisError::AssignmentMissing))?;
        let sub_wallet_var = FpVar::new_witness(cs.clone(), || self.sub_wallet_address.ok_or(SynthesisError::AssignmentMissing))?;

        // Constraint 1: Basic Temporal Validation (exp > iat)
        exp_var.enforce_cmp(&iat_var, std::cmp::Ordering::Greater, false)?;

        // Constraint 2: Initialize stable Poseidon configuration
        let config = get_poseidon_config();

        // Constraint 3: Level 0: Generate the initial leaf hash (master_address + sub_wallet_address)
        let mut current_sponge = PoseidonSpongeVar::new(cs.clone(), &config);
        current_sponge.absorb(&master_var)?;
        current_sponge.absorb(&sub_wallet_var)?;
        
        let mut current_hash = current_sponge.squeeze_field_elements(1)?
            .get(0).cloned().ok_or(SynthesisError::AssignmentMissing)?;

        // Constraint 4: Submit the 4 levels of the tree by applying conditional constraints based on the indices
        for i in 0..4 {
            let sibling_val = self.path_elements.get(i).cloned().flatten().ok_or(SynthesisError::AssignmentMissing)?;
            let index_val = self.path_indices.get(i).cloned().flatten().ok_or(SynthesisError::AssignmentMissing)?;

            let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling_val))?;
            let index_var = Boolean::new_witness(cs.clone(), || Ok(index_val))?;

            // If index is true (1): the sibling is on the right, so the pair is (current_hash, sibling)
            // If index is false (0): the sibling is on the left, so the pair is (sibling, current_hash)
            let left_node = FpVar::conditionally_select(&index_var, &current_hash, &sibling_var)?;
            let right_node = FpVar::conditionally_select(&index_var, &sibling_var, &current_hash)?;

            // Constraint 5: Hash the pair of nodes to generate the next level's hash
            let mut loop_sponge = PoseidonSpongeVar::new(cs.clone(), &config);
            loop_sponge.absorb(&left_node)?;
            loop_sponge.absorb(&right_node)?;

            current_hash = loop_sponge.squeeze_field_elements(1)?
                .get(0).cloned().ok_or(SynthesisError::AssignmentMissing)?;
        }

        // Constraint 6: Force the calculated root at the top of the tree to be EQUAL to the public root sent
        current_hash.enforce_equal(&root_var)?;

        Ok(())
    }
}

// ==========================================
// 2. The Generator (Client-Side Prover)
// ==========================================
#[wasm_bindgen]
pub fn client_generate_proof(
    master_hex: &str,
    sub_wallet_hex: &str,
    root_hex: &str,
    iat: u64,
    exp: u64,
    path_elements_js: Box<[JsValue]>, // Receives the sibling hashes from JS
    path_indices_js: Box<[u8]>,       // Changed to u8 for wasm_bindgen to accept perfectly
    proving_key_hex: &str,
) -> Result<String, JsValue> {
    let master = fr_from_hex_wasm(master_hex)?;
    let sub_wallet = fr_from_hex_wasm(sub_wallet_hex)?;
    let root = fr_from_hex_wasm(root_hex)?;
    let iat_f = Fr::from(iat);
    let exp_f = Fr::from(exp);

    // Parsing of path elements coming from the Front-end
    let mut path_elements = Vec::new();
    for val in path_elements_js.iter() {
        let hex_str = val.as_string().ok_or_else(|| JsValue::from_str("ERR_INVALID_PATH_ELEMENT_STR"))?;
        path_elements.push(Some(fr_from_hex_wasm(&hex_str)?));
    }

    // Safe mapping from u8 (0 or 1) to Option<bool> that the circuit needs
    let path_indices: Vec<Option<bool>> = path_indices_js.iter().map(|&b| Some(b != 0)).collect();

    if path_elements.len() != 4 || path_indices.len() != 4 {
        return Err(JsValue::from_str("ERR_MERKLE_PATH_DEPTH_MUST_BE_4"));
    }

    let pk_bytes = hex::decode(proving_key_hex.trim_start_matches("0x"))
        .map_err(|_| JsValue::from_str("ERR_INVALID_PK_HEX"))?;
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .map_err(|_| JsValue::from_str("ERR_DESERIALIZE_PK"))?;

    let circuit = IdentiFIClusterCircuit {
        master_address: Some(master),
        sub_wallet_address: Some(sub_wallet),
        commitment_root: Some(root),
        timestamp_exp: Some(exp_f),
        timestamp_iat: Some(iat_f),
        path_elements,
        path_indices,
    };

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| JsValue::from_str("ERR_ENTROPY_FAILED"))?;
    let mut rng = StdRng::from_seed(seed);
    
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|_| JsValue::from_str("ERR_PROVING_FAILED"))?;

    let mut serialized_proof = Vec::new();
    proof.serialize_compressed(&mut serialized_proof)
        .map_err(|_| JsValue::from_str("ERR_SERIALIZE_PROOF"))?;

    Ok(format!("0x{}", hex::encode(serialized_proof)))
}

// ==========================================
// 3. The Auditor (Client/Server-Side Verifier)
// ==========================================
#[wasm_bindgen]
pub fn client_verify_proof(
    proof_hex: &str,
    root_hex: &str,
    iat: u64,
    exp: u64,
    verifying_key_hex: &str,
) -> Result<bool, JsValue> {
    let root = fr_from_hex_wasm(root_hex)?;
    let iat_f = Fr::from(iat);
    let exp_f = Fr::from(exp);

    // The exposed public inputs remain exactly the same (Root, Exp, Iat)
    let public_inputs = vec![root, exp_f, iat_f];

    let proof_bytes = hex::decode(proof_hex.trim_start_matches("0x"))
        .map_err(|_| JsValue::from_str("ERR_INVALID_PROOF_HEX"))?;
    let proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes[..])
        .map_err(|_| JsValue::from_str("ERR_DESERIALIZE_PROOF"))?;

    let vk_bytes = hex::decode(verifying_key_hex.trim_start_matches("0x"))
        .map_err(|_| JsValue::from_str("ERR_INVALID_VK_HEX"))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .map_err(|_| JsValue::from_str("ERR_DESERIALIZE_VK"))?;

    let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .map_err(|_| JsValue::from_str("ERR_VERIFICATION_CRASH"))?;

    Ok(is_valid)
}