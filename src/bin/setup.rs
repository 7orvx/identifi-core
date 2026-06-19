use ark_bn254::Bn254;
use ark_ff::Zero;                        // Import Fr::zero()
use ark_groth16::Groth16;
use ark_snark::CircuitSpecificSetupSNARK; // setup()
use ark_std::rand::{SeedableRng};          // seed_from_u64()
use identifi_core::{IdentiFIClusterCircuit, Fr}; 
use ark_serialize::CanonicalSerialize;

fn main() {
    // Initialize fictitious values set to zero to satisfy Groth16 constraints
    let fake_field = Fr::zero();
    
    // 1. Create circuit with populated structures (values do not alter universal setup)
    let circuit = IdentiFIClusterCircuit {
        master_address: Some(fake_field),
        sub_wallet_address: Some(fake_field),
        commitment_root: Some(fake_field),
        timestamp_exp: Some(Fr::from(2)), // exp (2) > iat (1) for pass the temporal check
        timestamp_iat: Some(Fr::from(1)),
        path_elements: vec![Some(fake_field); 4], // Fill 4 levels with dummy fields
        path_indices: vec![Some(false); 4],       // Fill with dummy directions (false)
    };

    println!("Starting mathematical synthesis of the circuit (Setup Groth16)...");

    // 2. Generate the keys
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng).unwrap();

    // 3. Save keys in hex files
        let mut pk_bytes = Vec::new();
                pk.serialize_compressed(&mut pk_bytes).unwrap();
                std::fs::write("proving_key.hex", hex::encode(pk_bytes)).expect("Error saving PK");

        let mut vk_bytes = Vec::new();
            vk.serialize_compressed(&mut vk_bytes).unwrap();
                std::fs::write("verifying_key.hex", hex::encode(vk_bytes)).expect("Error saving VK");
    
    println!("Keys generated successfully!");
}