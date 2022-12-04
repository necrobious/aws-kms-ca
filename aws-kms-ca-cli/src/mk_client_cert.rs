use std::error::Error;
use aws_sdk_kms as kms;
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
use aws_kms_ca_x509::certificate::{
    X509Version,
    SerialNumber,
    SubjectPublicKeyInfo,
    KeyAlgorithmIdentifier,
    CommonName,
    ToBeSignedCertificate,
    SignatureAlgorithmIdentifier,
    Certificate,
};
use aws_kms_ca_x509::certificate::extensions::{
    Extension,
    KeyUsage,
    KeyUsages,
    BasicConstraints,
    KeyPurpose,
    ExtendedKeyUsage,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
};
use std::default::Default;
use clap::Parser;
//use std::str::FromStr;
use bytes::Bytes;
use time::OffsetDateTime;
use hex;

const KMS_SIGNING_ALGORITHM_SHA_256: &'static str = "ECDSA_SHA_256";
const KMS_SIGNING_ALGORITHM_SHA_384: &'static str = "ECDSA_SHA_384";

fn auth_key_id_parser (input: &str) -> Result<AuthorityKeyIdentifier, String> {
    hex::decode(input)
        .map(AuthorityKeyIdentifier)
        .map_err(|e| e.to_string())
}

fn signing_algorithm_parser (input: &str) -> Result<SignatureAlgorithmIdentifier, String> {
    use SignatureAlgorithmIdentifier::*;
    match input {
        KMS_SIGNING_ALGORITHM_SHA_256 => Ok(EcdsaWithSha256),
        KMS_SIGNING_ALGORITHM_SHA_384 => Ok(EcdsaWithSha384),
        _ => Err(format!("Unsupported signing algorithm: {}", input)) 
    }
}

#[derive(Parser, Debug)]
#[command(name = "mk_client_cert")]
#[command(about = "Generate a new keypair, construct the to-be-signed binary output, suiable to send to the KMS CMK to self-sign.", long_about = None)]
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

    #[arg(
        long,
        short = 'c',
        value_name = "COMMON_NAME",
        required = true,
        help = "The Commanon Name of the subject."
    )]
    common_name: String, 

    #[arg(
        long,
        short = 'a',
        value_name = "HEX_DIGEST",
        required = true,
        value_parser = auth_key_id_parser,
        help = "The hex string of the Authority Key ID."
    )]
    auth_key_id: AuthorityKeyIdentifier, 

    #[arg(
        long,
        short = 's',
        value_name = "KMS_SIGNING_ALGORITHM",
        required = true,
        value_parser = signing_algorithm_parser,
        help = "The AWS KMS algorithm to use when sigining certificates. ECDSA_SHA_256, ECDSA_SHA_384"
    )]
    signing_algorithm: SignatureAlgorithmIdentifier,
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

    let now = OffsetDateTime::now_utc().replace_nanosecond(0) // any non-zero .nanosecond()
        .map_err(|e| e.to_string())?;                         // OffsetDateTime value will cause
                                                              // yasna's UTCTime from_datetime()
                                                              // to fail and assert(panic)

    let iss_cn = CommonName(args.key_id.clone());
    let sub_cn = CommonName(args.common_name);
    let builder = ToBeSignedCertificate::builder()
        .version(X509Version::V3)
        .serial(sn)
        .signature_algorithm(args.signing_algorithm)
        .issuer_cn(&iss_cn)
        .valid_days(now, args.days as i64)
        .subject_cn(&sub_cn)
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
        .extension(Extension::from(args.auth_key_id)); //AuthorityKeyIdentifier

    let tbs_cert = builder.build()?;

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
