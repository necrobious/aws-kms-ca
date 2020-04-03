use rusoto_core::region::Region;
use rusoto_kms::{
    GetPublicKeyRequest,
    GetPublicKeyResponse,
    SignRequest,
    KmsClient,
    Kms
};
use std::default::Default;
use clap::{Arg, App};
use std::str::FromStr;
use bytes::Bytes;
use ring::rand::{SystemRandom, SecureRandom};
use ring::digest::{digest, SHA512_256};
use aws_kms_ca::certificate::x509_version::X509Version;
use aws_kms_ca::certificate::serial_number::SerialNumber;
use aws_kms_ca::certificate::signature_algorithm_identifier::SignatureAlgorithmIdentifier;
use aws_kms_ca::certificate::subject_public_key_info::SubjectPublicKeyInfo;
use aws_kms_ca::certificate::extensions::{
    Extension,
    KeyUsage,
    KeyUsages,
    BasicConstraints,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
};

use aws_kms_ca::certificate::key_algorithm_identifier::KeyAlgorithmIdentifier;
use aws_kms_ca::certificate::common_name::CommonName;
use aws_kms_ca::certificate::to_be_signed_certificate::ToBeSignedCertificate;
use aws_kms_ca::certificate::Certificate;
use chrono::prelude::*;
use std::error::Error;

const KMS_SPEC_ECC_NIST_P384: &'static str = "ECC_NIST_P384";
const KMS_SPEC_ECC_NIST_P256: &'static str = "ECC_NIST_P256";
const KMS_SIGNING_ALGORITHM_SHA_256: &'static str = "ECDSA_SHA_256";
const KMS_SIGNING_ALGORITHM_SHA_384: &'static str = "ECDSA_SHA_384";

// Expects the ASN.1 DER encoding of a P-384 public key
// Removes the ASN.1 DER packagying and returns the raw key bytes.
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
// Removes the ASN.1 DER packagying and returns the raw key bytes.
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

fn get_kms_pub_key_bytes (res:GetPublicKeyResponse) -> Result<SubjectPublicKeyInfo, String> {
    match (res.public_key, res.customer_master_key_spec) {
        (Some(bytes), Some(spec)) if spec == KMS_SPEC_ECC_NIST_P384 => {
            get_p384_pkey(&bytes[..]).map(|pk|
                SubjectPublicKeyInfo {
                    algorithm: KeyAlgorithmIdentifier::P384,
                    public_key: pk.as_ref().to_vec(),
                }
            ).ok_or("invalid or unexpected P384 public key".to_string())
        },
        (Some(bytes), Some(spec)) if spec == KMS_SPEC_ECC_NIST_P256 => {
            get_p256_pkey(&bytes[..]).map(|pk|
                SubjectPublicKeyInfo {
                    algorithm: KeyAlgorithmIdentifier::P256,
                    public_key: pk.as_ref().to_vec(),
                }
            ).ok_or("invalid or unexpected P256 public key".to_string())
        },
        _ => Err("Could not determine Public Key from spec".to_string())
    }
}

fn is_aws_region (input:String) -> Result<(), String> {
    Region::from_str(input.as_ref()).map(|_| ()).map_err(|e| e.to_string())
}

fn is_number (input:String) -> Result<(), String> {
    input.parse::<usize>().map(|_| ()).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main () -> Result<(), Box<dyn Error>> {
    let sysrand = SystemRandom::new();
    let matches = App::new("mk_ca_cert")
        .about("Get an AWS KMS asym CMK's Public Key, construct the to-be-signed binary output, suiable to send to the KMS CMK to self-sign.")
        .arg(Arg::with_name("key_id")
             .short("k")
             .long("key_id")
             .value_name("ARN")
             .help("Identifies the asymmetric CMK that includes the public key.")
             .takes_value(true)
             .required(true))
        .arg(Arg::with_name("region")
             .short("r")
             .long("region")
             .value_name("AWS_REGION")
             .help("AWS region to connect to KMS")
             .takes_value(true)
             .required(true)
             .validator(is_aws_region))
         .arg(Arg::with_name("days")
             .short("d")
             .long("days")
             .value_name("DAYS_VALID")
             .help("Number of days the certificate should be valid for.")
             .takes_value(true)
             .required(true)
             .validator(is_number))
        .get_matches();

    let region = matches
        .value_of("region")
        .and_then(|r| Region::from_str(r).ok())
        .unwrap();

    let days = matches
        .value_of("days")
        .and_then(|d| d.parse::<usize>().ok() )
        .unwrap();


    let key_id = matches
        .value_of("key_id")
        .map(|k| k.to_string() )
        .unwrap();

    // build random serial number
    let mut sn_bytes = [0u8;19];
    sysrand.fill(&mut sn_bytes).map_err(|_| "could not generate random serial number")?;
    let sn = SerialNumber::new(sn_bytes);

    let kms_client = KmsClient::new(region);

    let get_pub_key_request = GetPublicKeyRequest{
        key_id: key_id.clone(),
        ..Default::default()
    };

    let now = Utc::now();

    let tbs_cert =
        kms_client.get_public_key(get_pub_key_request).await
            .map_err(|e| e.to_string())
            .and_then(|get_pub_key_response| get_kms_pub_key_bytes(get_pub_key_response))
            .and_then(|spki| {
                let skid =
                    digest(&SHA512_256, &spki.public_key[..])
                        .as_ref()
                        .to_vec();
                ToBeSignedCertificate::builder()
                    .version(X509Version::V3)
                    .serial(sn)
                    .valid_days(now, days as i64)
                    .issuer_cn(CommonName(key_id.clone()))
                    .subject_cn(CommonName(key_id.clone()))
                    .subject_public_key_info(spki)
                    .extension(Extension::from(BasicConstraints{
                        ca: true,
                        ..Default::default()
                    }))
                    .extension(Extension::from(KeyUsages(vec!(
                        KeyUsage::KeyCertSign,
                        KeyUsage::CrlSign,
                    ))))
                    .extension(Extension::from(SubjectKeyIdentifier(
                        skid.clone()
                    )))
                    .extension(Extension::from(AuthorityKeyIdentifier(
                        skid.clone()
                    )))
                    .build()
            })?;

    let signature_algorithm = tbs_cert.signature_algorithm.clone();

    let sign_request = SignRequest {
        key_id: key_id.clone(),
        message: Bytes::from(tbs_cert.clone()),
        message_type: Some("RAW".to_string()),
        signing_algorithm: {
            use SignatureAlgorithmIdentifier::*;
            match signature_algorithm {
                EcdsaWithSha256 => KMS_SIGNING_ALGORITHM_SHA_256,
                EcdsaWithSha384 => KMS_SIGNING_ALGORITHM_SHA_384,
            }.to_string()
        },
        ..Default::default()
    };

    let signature =
        kms_client.sign(sign_request).await
            .map_err(|e| e.to_string())
            .and_then(|sign_response|
                sign_response.signature.ok_or("signature unavailable!".to_string()))?;

    let ca_cert = Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: signature_algorithm,
        signature_value: signature,
    };

    let pem = base64::encode(&Bytes::from(ca_cert)[..]);

    println!("-----BEGIN CERTIFICATE-----");
    for (i, c) in pem.chars().enumerate() {
        if (i != 0) && (i % 64 ==0) { println!("");}
        print!("{}",c);
    }
    println!("");
    println!("-----END CERTIFICATE-----");

    Ok(())
}
