use std::error::Error;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SigPublicKey, SecretKey as SigSecretKey, SignedMessage};
use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;

// Re-export specific types mapping to the Po8 Spec
// ML-DSA-65 maps to Dilithium3
pub use pqcrypto_dilithium::dilithium3::{
    keypair as dsa_keypair, 
    sign as dsa_sign,
    detached_sign as dsa_detached_sign, 
    verify_detached_signature as dsa_verify,
    PublicKey as MlDsaPublicKey,
    SecretKey as MlDsaSecretKey,
    DetachedSignature as MlDsaSignature,
};

// ML-KEM-768 maps to Kyber768
pub use pqcrypto_kyber::kyber768::{
    keypair as kem_keypair,
    encapsulate as kem_encapsulate,
    decapsulate as kem_decapsulate,
    PublicKey as MlKemPublicKey,
    SecretKey as MlKemSecretKey,
    Ciphertext as MlKemCiphertext,
    SharedSecret as MlKemSharedSecret,
};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub trait QuantumSigner {
    fn generate_keypair() -> Result<KeyPair, Box<dyn Error + Send + Sync>>;
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, Box<dyn Error + Send + Sync>>;
}

pub struct MlDsa65;

impl QuantumSigner for MlDsa65 {
    fn generate_keypair() -> Result<KeyPair, Box<dyn Error + Send + Sync>> {
        let (pk, sk) = dsa_keypair();
        Ok(KeyPair {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let sk = MlDsaSecretKey::from_bytes(secret_key).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let signature = dsa_detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let pk = MlDsaPublicKey::from_bytes(public_key).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let sig = MlDsaSignature::from_bytes(signature).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        
        match dsa_verify(&sig, message, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// Hybrid Key Exchange (X25519 + ML-KEM-768)
pub struct HybridKEM;

#[derive(Debug)]
pub struct HybridKeyPair {
    pub x25519_pk: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

#[derive(Debug)]
pub struct HybridCiphertext {
    pub x25519_ephemeral_pk: [u8; 32],
    pub mlkem_ct: Vec<u8>,
}

impl HybridKEM {
    pub fn generate_keypair() -> Result<HybridKeyPair, Box<dyn Error + Send + Sync>> {
        // 1. Generate X25519
        let x_secret = EphemeralSecret::random_from_rng(OsRng);
        let x_public = X25519PublicKey::from(&x_secret);
        
        // 2. Generate ML-KEM-768
        let (k_pk, k_sk) = kem_keypair();

        // Extract bytes for X25519 secret (hacky for storage, usually EphemeralSecret is opaque)
        // We'll re-generate for this scaffold or just store what we can. 
        // x25519-dalek 2.0 doesn't easily expose secret bytes from EphemeralSecret. 
        // We'll use StaticSecret for long-term identity keys.
        let static_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let static_public = X25519PublicKey::from(&static_secret);

        Ok(HybridKeyPair {
            x25519_pk: static_public.to_bytes(),
            x25519_sk: static_secret.to_bytes(),
            mlkem_pk: k_pk.as_bytes().to_vec(),
            mlkem_sk: k_sk.as_bytes().to_vec(),
        })
    }

    /// Initiator: Generates ephemeral keys, encapsulates to peer, derives shared secret
    pub fn encapsulate(
        peer_x25519_pk: &[u8; 32],
        peer_mlkem_pk: &[u8]
    ) -> Result<(HybridCiphertext, [u8; 32]), Box<dyn Error + Send + Sync>> {
        // 1. X25519 Diffie-Hellman
        let my_ephemeral_sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_ephemeral_pk = X25519PublicKey::from(&my_ephemeral_sk);
        let peer_static_pk = X25519PublicKey::from(*peer_x25519_pk);
        
        let dh_secret = my_ephemeral_sk.diffie_hellman(&peer_static_pk);

        // 2. ML-KEM Encapsulate
        let kem_pk = MlKemPublicKey::from_bytes(peer_mlkem_pk).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let (kem_ss, kem_ct) = kem_encapsulate(&kem_pk);

        // 3. HKDF Combine
        // K = HKDF( DH || KEM )
        let hkdf = Hkdf::<Sha256>::new(None, &[dh_secret.as_bytes(), kem_ss.as_bytes()].concat());
        let mut session_key = [0u8; 32];
        hkdf.expand(b"Po8_Hybrid_Handshake", &mut session_key).map_err(|_| Box::<dyn Error + Send + Sync>::from("HKDF failed"))?;

        Ok((
            HybridCiphertext {
                x25519_ephemeral_pk: my_ephemeral_pk.to_bytes(),
                mlkem_ct: kem_ct.as_bytes().to_vec(),
            },
            session_key
        ))
    }

    /// Responder: Decapsulates using long-term keys
    pub fn decapsulate(
        ciphertext: &HybridCiphertext,
        my_x25519_sk: &[u8; 32],
        my_mlkem_sk: &[u8]
    ) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        // 1. X25519 Diffie-Hellman
        let my_static_sk = x25519_dalek::StaticSecret::from(*my_x25519_sk);
        let peer_ephemeral_pk = X25519PublicKey::from(ciphertext.x25519_ephemeral_pk);
        
        let dh_secret = my_static_sk.diffie_hellman(&peer_ephemeral_pk);

        // 2. ML-KEM Decapsulate
        let kem_sk = MlKemSecretKey::from_bytes(my_mlkem_sk).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let kem_ct = MlKemCiphertext::from_bytes(&ciphertext.mlkem_ct).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let kem_ss = kem_decapsulate(&kem_ct, &kem_sk);

        // 3. HKDF Combine
        let hkdf = Hkdf::<Sha256>::new(None, &[dh_secret.as_bytes(), kem_ss.as_bytes()].concat());
        let mut session_key = [0u8; 32];
        hkdf.expand(b"Po8_Hybrid_Handshake", &mut session_key).map_err(|_| Box::<dyn Error + Send + Sync>::from("HKDF failed"))?;

        Ok(session_key)
    }
}
