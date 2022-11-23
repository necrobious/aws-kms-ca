use aws_sdk_kms as kms;
use std::default::Default;
use clap::Parser;
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
use time::OffsetDateTime;
use std::error::Error;

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

fn get_kms_pub_key_bytes (res:kms::output::GetPublicKeyOutput) -> Result<SubjectPublicKeyInfo, String> {
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
        _ => {
            Err("Could not determine Public Key from spec".to_string())
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "mk_ca_cert")]
#[command(about = "Get an AWS KMS asym CMK's Public Key, construct the to-be-signed binary output, suiable to send to the KMS CMK to self-sign.", long_about = None)]
struct Cli {
    #[arg(
        long,
        short = 'k',
        value_name = "ARN",
        required = true,
        help = "Identifies the asymmetric CMK that includes the public key."
    )]
    key_id: String, 
   
    #[arg(
        long,
        short = 'd',
        value_name = "DAYS_VALID",
        required = true,
        value_parser = clap::value_parser!(usize), 
        help = "Number of days the certificate should be valid for."
    )]
    days: usize,
}

#[tokio::main]
async fn main () -> Result<(), Box<dyn Error>> {
    let sysrand = SystemRandom::new();
    let args = Cli::parse();

    // build random serial number
    let mut sn_bytes = [0u8;19];
    sysrand.fill(&mut sn_bytes).map_err(|_| "could not generate random serial number")?;
    let sn = SerialNumber::new(sn_bytes);

    let aws_env_config = aws_config::load_from_env().await;
    let kms_client = kms::Client::new(&aws_env_config);

    let now = OffsetDateTime::now_utc().replace_nanosecond(0) // any non-zero .nanosecond()
        .map_err(|e| e.to_string())?;                         // OffsetDateTime value will cause
                                                              // yasna's UTCTime from_datetime()
                                                              // to fail and assert(panic)

    let kms_get_pkey_resp = kms_client
        .get_public_key()
        .key_id(args.key_id.clone())
        .send()
        .await?;

    let spki = get_kms_pub_key_bytes(kms_get_pkey_resp)?; 
    let skid = digest(&SHA512_256, &spki.public_key[..])
        .as_ref()
        .to_vec();

    let tbs_cert = ToBeSignedCertificate::builder()
        .version(X509Version::V3)
        .serial(sn)
        .valid_days(now, args.days as i64)
        .issuer_cn(CommonName(args.key_id.clone()))
        .subject_cn(CommonName(args.key_id.clone()))
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
        .build()?;

    let signature_algorithm = tbs_cert.signature_algorithm.clone();

    let kms_sign_resp = kms_client
        .sign()
        .key_id(args.key_id.clone())
        .message(kms::types::Blob::new(Bytes::from(tbs_cert.clone())))
        .message_type(kms::model::MessageType::Raw)
        .signing_algorithm({
            use SignatureAlgorithmIdentifier::*;
            use kms::model::SigningAlgorithmSpec::*; 
            match signature_algorithm {
                EcdsaWithSha256 => EcdsaSha256,
                EcdsaWithSha384 => EcdsaSha384,
            }
        })
        .send()
        .await?;

    let signature = kms_sign_resp
        .signature()
        .ok_or("signature unavailable!".to_string())
        .map(|blob| Bytes::copy_from_slice(blob.as_ref()))?;

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
