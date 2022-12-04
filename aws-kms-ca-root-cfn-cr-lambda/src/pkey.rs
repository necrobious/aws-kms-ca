use aws_sdk_kms as kms;
use aws_kms_ca_x509::certificate::subject_public_key_info::SubjectPublicKeyInfo;
use aws_kms_ca_x509::certificate::key_algorithm_identifier::KeyAlgorithmIdentifier;

// Expects the ASN.1 DER encoding of a P-384 public key
// Removes the ASN.1 DER packaging and returns the raw key bytes.
pub fn get_p384_pkey <'a> (public_key: &'a[u8]) -> Option<&'a[u8]> {
    match public_key {
        [0x30,0x76, // SEQUENCE, 118 bytes
            0x30,0x10, // SEQUENCE, 16 bytes
                0x06,0x07, // OID, 7 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,// encoding of OID(1.2.840.10045.2.1) RFC 5480 2.1.1 - ecPublicKey
                0x06,0x05, // OID, 5 Bytes
                    0x2b,0x81,0x04,0x00,0x22, // encoding of OID(1.3.132.0.34) RFC 5480 2.1.1.1 - secp384r1
            0x03,0x62,0x00, // BIT STRING, 98 bytes, 0 unused
                pkey @ ..] => Some(pkey), // 97 bytes, 1 byte uncompressed indicator (0x04), 96 byte public key
        _ => None
    }
}

// Expects the ASN.1 DER encoding of a P-256 public key
// Removes the ASN.1 DER packaging and returns the raw key bytes.
pub fn get_p256_pkey <'a> (public_key: &'a[u8]) -> Option<&'a[u8]> {
    match public_key {
        [0x30,0x59, // SEQUENCE, 89 bytes
            0x30,0x13, // SEQUENCE,
                0x06,0x07, // OID, 7 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,// encoding of OID(1.2.840.10045.2.1) RFC 5480 2.1.1 - ecPublicKey
                0x06,0x08, // OID, 8 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,// encoding of OID(1.2.840.10045.3.1.7) RFC 5480 2.1.1.1 - secp256r1
            0x03,0x42,0x00, // BIT STRING, 66 bytes, 0 unused
                pkey @ ..] => Some(pkey), // 65 bytes, 1 byte uncompressed indicator (0x04), 64 byte public key
        _ => None
    }
}

pub fn get_kms_pub_key_bytes (res:kms::output::GetPublicKeyOutput) -> Result<SubjectPublicKeyInfo, String> {
    use kms::model::KeySpec::*;
    use KeyAlgorithmIdentifier::*;
    match (res.public_key(), res.key_spec()) {
        (Some(blob), Some(spec)) if *spec == EccNistP384 => {
            get_p384_pkey(blob.as_ref())
                .ok_or("invalid or unexpected P384 public key".to_string())
                .map(|pk| SubjectPublicKeyInfo {
                    algorithm: P384,
                    public_key: pk.as_ref().to_vec(),
                })
        },
        (Some(blob), Some(spec)) if *spec == EccNistP256 => {
            get_p256_pkey(blob.as_ref())
                .ok_or("invalid or unexpected P256 public key".to_string())
                .map(|pk| SubjectPublicKeyInfo {
                    algorithm: KeyAlgorithmIdentifier::P256,
                    public_key: pk.as_ref().to_vec(),
                })
        },
        (pkey, spec) => {
            Err(format!("Could not determine Public Key from spec; pub key: {:?}; spec: {:?}", pkey, spec))
        }
    }
}


