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
    FieldBasedCryptographicSponge,
    poseidon::{PoseidonConfig, PoseidonSponge},
};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;

use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ==========================================
// HELPER: SECURE HEX PARSER (Uniquely Mapped)
// ==========================================
fn fr_from_hex(hex_str: &str) -> Result<Fr, String> {
    let clean_hex = hex_str.trim_start_matches("0x");
    let mut bytes = hex::decode(clean_hex).map_err(|_| "ERR_HEX_DECODE".to_string())?;
    
    let mut padded_bytes = [0u8; 32];
    if bytes.len() <= 32 {
        padded_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
    } else {
        bytes.zeroize();
        return Err("ERR_FIELD_OVERFLOW".to_string());
    }
    
    bytes.zeroize(); // clear temporary bytes allocated by hex::decode
    let field_element = Fr::from_be_bytes_mod_order(&padded_bytes);
    padded_bytes.zeroize();
    
    Ok(field_element)
}

fn fr_from_hex_wasm(hex_str: &str) -> Result<Fr, JsValue> {
    fr_from_hex(hex_str).map_err(|e| JsValue::from_str(&e))
}

// Initialize stable Poseidon parameters for BN254 using fixed seed generator
fn get_poseidon_config() -> PoseidonConfig<Fr> {
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 5;

    let (ark, mds) = ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds::<Fr>(
        254,
        3,   
        full_rounds,
        partial_rounds,
        alpha,
    );

    let real_width = mds.len(); 
    let real_capacity = real_width - 2; 

    PoseidonConfig::<Fr>::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        2,   
        real_capacity, 
    )
}

// Native Poseidon helper exported to WASM (Pure calculation in JS)
#[wasm_bindgen]
pub fn compute_poseidon_native(master_hex: &str, sub_hex: &str) -> Result<String, JsValue> {
    let mut a = fr_from_hex_wasm(master_hex)?;
    let mut b = fr_from_hex_wasm(sub_hex)?;

    let config = get_poseidon_config(); 
    let mut sponge = PoseidonSponge::new(&config);

    sponge.absorb(&a);
    sponge.absorb(&b);
    let output = sponge.squeeze_native_field_elements(1).get(0)
        .copied()
        .ok_or_else(|| JsValue::from_str("ERR_SQUEEZE_FAILED"))?;

    // THE PURGE: clear local native variables immediately after calculation
    a.zeroize();
    b.zeroize();

    let big_int: <Fr as PrimeField>::BigInt = output.into();
    let be_bytes = big_int.to_bytes_be();
    Ok(format!("0x{}", hex::encode(be_bytes)))
}

// Unified Poseidon Export utility to calculate deterministic added root
#[wasm_bindgen]
pub fn compute_commitment_root_wasm(master_hex: &str, sub_hex: &str) -> Result<String, JsValue> {
    let mut master = fr_from_hex_wasm(master_hex)?;
    let mut sub = fr_from_hex_wasm(sub_hex)?;

    let root = master + sub;

    master.zeroize();
    sub.zeroize();

    let big_int: <Fr as PrimeField>::BigInt = root.into();
    let be_bytes = big_int.to_bytes_be();
    Ok(format!("0x{}", hex::encode(be_bytes)))
}

// ==========================================
// 1. THE IDENTIFI v2.0 CIRCUIT
// ==========================================
// Added the macro Zeroize and ZeroizeOnDrop to ensure controlled destruction
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentiFIClusterCircuit {
    pub master_address: Option<Fr>,       // Private Witness
    pub sub_wallet_address: Option<Fr>,   // Private Witness
    
    #[zeroize(skip)]                      // Skip public data in the purge routines
    pub commitment_root: Option<Fr>,      
    #[zeroize(skip)]
    pub timestamp_exp: Option<Fr>,        
    #[zeroize(skip)]
    pub timestamp_iat: Option<Fr>,        
    
    pub path_elements: Vec<Option<Fr>>,   // Sibling hashes private
    #[zeroize(skip)]
    pub path_indices: Vec<Option<bool>>,  
}

impl ConstraintSynthesizer<Fr> for IdentiFIClusterCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root_var = FpVar::new_input(cs.clone(), || self.commitment_root.ok_or(SynthesisError::AssignmentMissing))?;
        let exp_var = FpVar::new_input(cs.clone(), || self.timestamp_exp.ok_or(SynthesisError::AssignmentMissing))?;
        let iat_var = FpVar::new_input(cs.clone(), || self.timestamp_iat.ok_or(SynthesisError::AssignmentMissing))?;

        let master_var = FpVar::new_witness(cs.clone(), || self.master_address.ok_or(SynthesisError::AssignmentMissing))?;
        let sub_wallet_var = FpVar::new_witness(cs.clone(), || self.sub_wallet_address.ok_or(SynthesisError::AssignmentMissing))?;

        exp_var.enforce_cmp(&iat_var, std::cmp::Ordering::Greater, false)?;

        let config = get_poseidon_config();

        let mut current_sponge = PoseidonSpongeVar::new(cs.clone(), &config);
        current_sponge.absorb(&master_var)?;
        current_sponge.absorb(&sub_wallet_var)?;
        
        let mut current_hash = current_sponge.squeeze_field_elements(1)?
            .get(0).cloned().ok_or(SynthesisError::AssignmentMissing)?;

        for i in 0..4 {
            let sibling_val = self.path_elements.get(i).cloned().flatten().ok_or(SynthesisError::AssignmentMissing)?;
            let index_val = self.path_indices.get(i).cloned().flatten().ok_or(SynthesisError::AssignmentMissing)?;

            let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling_val))?;
            let index_var = Boolean::new_witness(cs.clone(), || Ok(index_val))?;

            let left_node = FpVar::conditionally_select(&index_var, &current_hash, &sibling_var)?;
            let right_node = FpVar::conditionally_select(&index_var, &sibling_var, &current_hash)?;

            let mut loop_sponge = PoseidonSpongeVar::new(cs.clone(), &config);
            loop_sponge.absorb(&left_node)?;
            loop_sponge.absorb(&right_node)?;

            current_hash = loop_sponge.squeeze_field_elements(1)?
                .get(0).cloned().ok_or(SynthesisError::AssignmentMissing)?;
        }

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
    path_elements_js: Box<[JsValue]>, 
    path_indices_js: Box<[u8]>,       
    proving_key_hex: &str,
) -> Result<String, JsValue> {
    let mut master = fr_from_hex_wasm(master_hex)?;
    let mut sub_wallet = fr_from_hex_wasm(sub_wallet_hex)?;
    let root = fr_from_hex_wasm(root_hex)?;
    let iat_f = Fr::from(iat);
    let exp_f = Fr::from(exp);

    let mut path_elements = Vec::new();
    for val in path_elements_js.iter() {
        let mut hex_str = val.as_string().ok_or_else(|| JsValue::from_str("ERR_INVALID_PATH_ELEMENT_STR"))?;
        let parsed = fr_from_hex_wasm(&hex_str);
        hex_str.zeroize();
        path_elements.push(Some(parsed?));
    }

    let path_indices: Vec<Option<bool>> = path_indices_js.iter().map(|&b| Some(b != 0)).collect();

    if path_elements.len() != 4 || path_indices.len() != 4 {
        // Fallback of clearing in case of abort due to invalid size
        master.zeroize();
        sub_wallet.zeroize();
        path_elements.iter_mut().for_each(|x| { if let Some(e) = x { e.zeroize(); } });
        return Err(JsValue::from_str("ERR_MERKLE_PATH_DEPTH_MUST_BE_4"));
    }

    let pk_bytes = hex::decode(proving_key_hex.trim_start_matches("0x"))
        .map_err(|_| JsValue::from_str("ERR_INVALID_PK_HEX"))?;
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .map_err(|_| JsValue::from_str("ERR_DESERIALIZE_PK"))?;

    // Construction of the circuit cloning the temporary witnesses
    let circuit = IdentiFIClusterCircuit {
        master_address: Some(master),
        sub_wallet_address: Some(sub_wallet),
        commitment_root: Some(root),
        timestamp_exp: Some(exp_f),
        timestamp_iat: Some(iat_f),
        path_elements: path_elements.clone(),
        path_indices,
    };

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| JsValue::from_str("ERR_ENTROPY_FAILED"))?;
    let mut rng = StdRng::from_seed(seed);
    seed.zeroize();
    
    // Execution of the Prover Groth16
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|_| {
            // In case of catastrophic error, apply the forced purge of local data
            master.zeroize();
            sub_wallet.zeroize();
            path_elements.iter_mut().for_each(|x| { if let Some(e) = x { e.zeroize(); } });
            JsValue::from_str("ERR_PROVING_FAILED")
        })?;

    // =========================================================================
    // THE PURGE: Aggressive reset of linear memory before delivery
    // =========================================================================
    master.zeroize();
    sub_wallet.zeroize();
    path_elements.iter_mut().for_each(|x| {
        if let Some(element) = x {
            element.zeroize();
        }
    });
    // The automatic Drop invokes the ZeroizeOnDrop of the 'circuit' struct, cleaning its internal instances

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