use rusoto_core::region::Region;
use rusoto_kms::{
    SignRequest,
    KmsClient,
    Kms
};
use ring::{
    rand::{SystemRandom, SecureRandom},
    signature::{
        KeyPair,
        EcdsaKeyPair,
        ECDSA_P384_SHA384_FIXED_SIGNING,
    },
    digest::{
        digest,
        SHA512_256
    },
};
use aws_kms_ca::certificate::{
    X509Version,
    SerialNumber,
    SubjectPublicKeyInfo,
    KeyAlgorithmIdentifier,
    CommonName,
    ToBeSignedCertificate,
    SignatureAlgorithmIdentifier,
    Certificate,
};
use aws_kms_ca::certificate::extensions::{
    Extension,
    KeyUsage,
    KeyUsages,
    BasicConstraints,
    KeyPurpose,
    ExtendedKeyUsage,
    SubjectAlternativeName,
    GeneralName,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
};
use std::default::Default;
use clap::{Arg, App};
use std::str::FromStr;
use bytes::Bytes;
use std::net::IpAddr;
use std::error::Error;
use chrono::prelude::*;
use hex;

const KMS_SIGNING_ALGORITHM_SHA_256: &'static str = "ECDSA_SHA_256";
const KMS_SIGNING_ALGORITHM_SHA_384: &'static str = "ECDSA_SHA_384";

fn is_aws_region (input:String) -> Result<(), String> {
    Region::from_str(input.as_ref()).map(|_| ()).map_err(|e| e.to_string())
}

fn is_number (input:String) -> Result<(), String> {
    input.parse::<usize>().map(|_| ()).map_err(|e| e.to_string())
}

fn is_hex (input:String) -> Result<(), String> {
    hex::decode(input).map(|_| ()).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main () -> Result<(), Box<dyn Error>> {
    let sysrand = SystemRandom::new();
    let matches = App::new("mk_client_cert")
        .about("Generate a new keypair, construct the to-be-signed binary output, suiable to send to the KMS CMK to self-sign.")
        .arg(Arg::with_name("key-id")
             .short("k")
             .long("key-id")
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
         .arg(Arg::with_name("common-name")
             .short("c")
             .long("common-name")
             .value_name("COMMON_NAME")
             .help("The Commanon Name of the subject")
             .takes_value(true)
             .required(true))
         // Supplied seperate, in the event the same CMK is rotated and points to new keying material.
         .arg(Arg::with_name("auth-key-id")
             .long("auth-key-id")
             .value_name("HEX_DIGEST")
             .help("The hex string of the Authority Key ID.")
             .takes_value(true)
             .required(true)
             .validator(is_hex))
         .arg(Arg::with_name("signing-algorithm")
             .long("signing-algorithm")
             .help("The algorithm to use when sigining.")
             .takes_value(true)
             .required(true)
             .possible_value(KMS_SIGNING_ALGORITHM_SHA_256)
             .possible_value(KMS_SIGNING_ALGORITHM_SHA_384))
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
        .value_of("key-id")
        .map(|k| k.to_string() )
        .unwrap();

    let akid = matches
        .value_of("auth-key-id")
        .ok_or("invalid authority key ID".to_string())
        .and_then(|akid| hex::decode(akid.to_string()).map_err(|e| e.to_string()))
        .unwrap();

    let cn = matches
        .value_of("common-name")
        .map(|cn| CommonName(cn.to_string()) )
        .unwrap();

    let signature_algorithm = matches
        .value_of("signing-algorithm")
        .and_then(|signing_algorithm| {
            use SignatureAlgorithmIdentifier::*;
            match signing_algorithm {
                KMS_SIGNING_ALGORITHM_SHA_256 => Some(EcdsaWithSha256),
                KMS_SIGNING_ALGORITHM_SHA_384 => Some(EcdsaWithSha384),
                _ => None
            }
        })
        .unwrap();

    // build random serial number
    let mut sn_bytes = [0u8;19];
    sysrand.fill(&mut sn_bytes).map_err(|_| "could not generate random serial number")?;
    let sn = SerialNumber::new(sn_bytes);

    let kms_client = KmsClient::new(region);

    let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &sysrand)
        .map_err(|e| e.to_string())?;

    let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8_doc.as_ref())
        .map_err(|e| e.to_string())?;

    let spki = SubjectPublicKeyInfo {
        algorithm: KeyAlgorithmIdentifier::P384,
        public_key: keypair.public_key().as_ref().to_vec(),
    };

    let skid =
        digest(&SHA512_256, &spki.public_key[..]).as_ref().to_vec();

    let now = Utc::now();

    let mut builder = ToBeSignedCertificate::builder()
        .version(X509Version::V3)
        .serial(sn)
        .signature_algorithm(signature_algorithm)
        .issuer_cn(CommonName(key_id.clone()))
        .valid_days(now, days as i64)
        .subject_cn(cn)
        .subject_public_key_info(spki) // key algo implicitly sets signature_algorithm if unset
        .extension(Extension::from(BasicConstraints::default()))
        .extension(Extension::from(KeyUsages(vec!(
            KeyUsage::DigitalSignature,
        ))))
        .extension(Extension::from(ExtendedKeyUsage(vec!(
            KeyPurpose::ClientAuth
        ))))
        .extension(Extension::from(SubjectKeyIdentifier(
            skid
        )))
        .extension(Extension::from(AuthorityKeyIdentifier(
            akid
        )));

    let tbs_cert = builder.build()?;

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

    let cert = Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: signature_algorithm,
        signature_value: signature,
    };

    let key_pem  = base64::encode(pkcs8_doc.as_ref());
    let cert_pem = base64::encode(&Bytes::from(cert)[..]);

    println!("-----BEGIN PRIVATE KEY-----"); //following rfc5958 sec 5 advice for .p8 private key format
    for (i, c) in key_pem.chars().enumerate() {
        if (i != 0) && (i % 64 ==0) { println!("");}
        print!("{}",c);
    }
    println!("");
    println!("-----END PRIVATE KEY-----");

    println!("-----BEGIN CERTIFICATE-----");
    for (i, c) in cert_pem.chars().enumerate() {
        if (i != 0) && (i % 64 ==0) { println!("");}
        print!("{}",c);
    }
    println!("");
    println!("-----END CERTIFICATE-----");

    Ok(())
}
