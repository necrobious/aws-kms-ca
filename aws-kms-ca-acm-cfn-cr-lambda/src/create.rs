use std::ops::Index;
use crate::ProviderConfig;
use crate::CreateResourceProperties;
use time::OffsetDateTime;
use bytes::Bytes;
use regex::Regex;
use lazy_static::lazy_static;
use ring::{
    rand::SecureRandom,
    pkcs8::Document,
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
use aws_custom_resource_provider_events::{
    ResponseStatus,
    ProviderResponse,
    ProviderResponseBuilder,
    ProviderRequestCreateEvent
};

use aws_kms_ca_x509::certificate::{
    Certificate,
    key_algorithm_identifier::KeyAlgorithmIdentifier,
    x509_version::X509Version,
    serial_number::SerialNumber,
    signature_algorithm_identifier::SignatureAlgorithmIdentifier,
    common_name::CommonName,
    to_be_signed_certificate::ToBeSignedCertificate,
    subject_public_key_info::SubjectPublicKeyInfo,
    extensions::{
        Extension,
        KeyPurpose,
        KeyUsage,
        KeyUsages,
        ExtendedKeyUsage,
        BasicConstraints,
        SubjectKeyIdentifier,
        AuthorityKeyIdentifier,
        SubjectAlternativeName,
        GeneralName,
    }
};

use serde_json::{ Value };
use tracing::info;
use aws_sdk_acm as acm;
use aws_sdk_kms as kms;


/// Create a x.509 certificate for a domain name, send it to the KMS-backed CA root CMK for signing,
/// place the certificate, the self-signed x.509 root certificate, and the private key into ACM.
///
///  1. Retrieve the KMS CMK ARN from the resource properties.
///     The ARN should identify an AWS CMK with the following 
///     key-policy permissions granted to this Custom Resource
///     Provider: 
///        kms:Verify
///        kms:DescribeKey
///        kms:Sign
///  2. Call KMS.describeKey() to retrieve the CMK's key description
///  3. Parse the PEM encoded x.509 certificate. retain the PEM format for use in #11
///  4. Send the parsed certificate data and signature to KMS for signature verification.
///  5. Construct a new KeyPair
///  6. PEM encode Private key for use in #11
///  7. Construct a new domain certificate using the parsed CA certificate as the issuing authority
///  8. Send the constructed domain certificate to KMS.Sign() to be signed.
///  9. Assemble the signature result from #8 with the tbs-certificate
///     into the final X.509 certificate.
/// 10. PEM encode the signed domain sert #9.
/// 11. Send the PEM encoded domain certificate, PEM encoded CA certificate, and PEM encoded
///     private key to ACM.ImportCertificate().
///
pub async fn create<'c,'e>(
    config: &'c ProviderConfig,
    event: &ProviderRequestCreateEvent<CreateResourceProperties>
) -> Result<ProviderResponse, ProviderResponse> {
    info!("create");

    let props = get_resource_properties(event)?; 
    let ca_cmk_descr = get_ca_cmk_description(config, event, &props).await?;
    let (ca_cert_pem, ca_cert) = parse_cert_from_description(event, &ca_cmk_descr)?;
    verify_cert_signature(config, event, &props, &ca_cert).await?;
    let (key_pem, spki) = new_p384_keypair(config, event)?;
    let tbs_cert = buid_domain_cert(config, event, &props, &ca_cert, &spki)?;
    let signed_cert = sign_certificate(config, event, &props, &tbs_cert).await?;
    let cert_pem = pem_encode_certificate(&signed_cert);
    let cert_arn = import_cert_into_acm(
        config,
        event,
        &key_pem,
        &cert_pem,
        &ca_cert_pem
    ).await?;

    let data = vec![("domain_cert_arn", Value::from(cert_arn))]
        .into_iter()
        .collect::<Value>();

    Ok(ProviderResponseBuilder::from_event_ref(event)
        .status(ResponseStatus::Success)
        .reason("Ok".to_string())
        .data(data)
        .build())
}

fn buid_domain_cert <'config, 'event,'props,'ca_cert,'spki>(
    config: &'config ProviderConfig,
    event: &'event ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'props CreateResourceProperties,
    ca_cert: &'ca_cert Certificate,
    spki: &'spki SubjectPublicKeyInfo,
) -> Result<ToBeSignedCertificate, ProviderResponse> {
    let sn = create_random_serial_number(config, event)?;
    let now = get_current_datetime(event)?;
    let signing_algorithm = parse_signing_algorithm(event, props)?;

    let issuer = ca_cert.tbs_certificate.subject.clone();

    let san = SubjectAlternativeName(props.domain_names
        .iter()
        .map(|domain_name| GeneralName::DnsName(domain_name.clone()))
        .collect::<Vec<GeneralName>>()
    );

    let sub_cn = props.domain_names
        .first()
        .map(|domain_name| CommonName(domain_name.clone()))
        .ok_or(
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("Could not find a domain name in the `domain_names` property to map to a x.509 common name value."))
                .build()
        )?;


    let skid = SubjectKeyIdentifier(digest(&SHA512_256, &spki.public_key[..]).as_ref().to_vec());

    let fuckadoodledo = ca_cert.tbs_certificate.extensions
        .iter()
        .filter(|ext| ext.is_subject_key_identifier())
        .map(|ext| AuthorityKeyIdentifier(ext.value.clone()))
        .collect::<Vec<AuthorityKeyIdentifier>>();
    let akid = fuckadoodledo
        .first()
        .ok_or(
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("Could not find CA certificate's Subject Key Identifier extension value"))
                .build()
        )?;

    let bc = BasicConstraints::default();
    let ku = KeyUsages(vec!(KeyUsage::DigitalSignature));
    let eku = ExtendedKeyUsage(vec!(KeyPurpose::ServerAuth));

    let tbs_cert = ToBeSignedCertificate::builder()
        .version(X509Version::V3)
        .serial(sn)
        .signature_algorithm(signing_algorithm)
        .issuer(issuer)
        .valid_days(now, 365 as i64)
        .subject_cn(&sub_cn)
        .subject_public_key_info(spki) // key algo implicitly sets signature_algorithm if unset
        .extension(Extension::from(bc))
        .extension(Extension::from(ku))
        .extension(Extension::from(eku))
        .extension(Extension::from(skid))
        .extension(Extension::from(akid)) 
        .extension(Extension::from(san))
        .build()
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to construct the x.509 certificate. props: {:?}; error: {:?}", &props, e))
                .build()
        )?;

    Ok(tbs_cert)
//    let signature_algorithm = tbs_cert.signature_algorithm.clone();

//unimplemented!()
}

   
async fn import_cert_into_acm<'config,'event,'request>(
    config: &'config ProviderConfig,
    event: &'event ProviderRequestCreateEvent<CreateResourceProperties>,
    key_pem: &'request str,
    cert_pem: &'request str,
    ca_cert_pem: &'request str
) -> Result<String, ProviderResponse> {
    info!("import_cert_into_acm");
    config.acm
        .import_certificate()
        .certificate(acm::types::Blob::new(cert_pem))
        .certificate_chain(acm::types::Blob::new(ca_cert_pem))
        .private_key(acm::types::Blob::new(key_pem))
        .send()
        .await
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to import certificate in ACM; {:?}", e))
                .build()
        )
        .and_then(|import_cert_output| import_cert_output.certificate_arn
            .map(|arn| String::from(arn))
            .ok_or(
                ProviderResponseBuilder::from_event_ref(event)
                    .status(ResponseStatus::Failed)
                    .reason(format!("Expected certificate ARN was unavailable after importing certificate!"))
                    .build()
            )
        )
}


const KMS_SIGNING_ALGORITHM_SHA_256: &'static str = "ECDSA_SHA_256";
const KMS_SIGNING_ALGORITHM_SHA_384: &'static str = "ECDSA_SHA_384";

fn parse_signing_algorithm <'event,'props> (
    event: &'event ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'props CreateResourceProperties,
) -> Result<SignatureAlgorithmIdentifier, ProviderResponse> {
    use SignatureAlgorithmIdentifier::*;
    match props.signing_algorithm.as_ref() {
        KMS_SIGNING_ALGORITHM_SHA_256 => Ok(EcdsaWithSha256),
        KMS_SIGNING_ALGORITHM_SHA_384 => Ok(EcdsaWithSha384),
        _ => Err(
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("Unsupported signing algorithm: {}", &props.signing_algorithm))
                .build()
        ) 
    }
}


fn new_p384_keypair <'config,'event> (
    config: &'config ProviderConfig,
    event: &'event ProviderRequestCreateEvent<CreateResourceProperties>,
) -> Result<(String, SubjectPublicKeyInfo), ProviderResponse> {
    let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &config.rnd)
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to create new keypair; {:?}", e))
                .build()
        )?;

    let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8_doc.as_ref())
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to decode new keypair; {:?}", e))
                .build()
        )?;

    let spki = SubjectPublicKeyInfo {
        algorithm: KeyAlgorithmIdentifier::P384,
        public_key: keypair.public_key().as_ref().to_vec(),
    };
    let key_pem = pem_encode_key(&pkcs8_doc);

    Ok( (key_pem, spki) )
}

fn parse_cert_from_description <'e, 's> (
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>,
    cert_descr: &'s str 
) -> Result<(String, Certificate), ProviderResponse> {
    lazy_static! {
        static ref FIND_CERT_REGEXP: Regex = Regex::new(r"(?m)-----BEGIN CERTIFICATE-----[\n]+((([0-9A-Za-z/+]{64}|[0-9A-Za-z=/+]{1,63}=)[\n])+)+-----END CERTIFICATE-----[\n]*").unwrap();
    }
    let (pem, b64) = FIND_CERT_REGEXP
        .captures(cert_descr)
        .map(|c| (
            String::from(c.index(0)),
            String::from(c.index(1).replace("\n",""))))
        .ok_or(
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("Could not find certificate in key description"))
                .build()
        )?;

    let der = base64::decode(&b64)
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to base64 decode PEM certificate data; {:?}", e))
                .build()
        )?;

    let cert = Certificate::try_from(Bytes::from(der))
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to parse DER ASN.1 certificate data; {:?}", e))
                .build()
        )?;

    Ok( (pem, cert) )
}

async fn get_ca_cmk_description <'c,'e,'p>(
    config: &'c ProviderConfig,
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'p CreateResourceProperties,
) -> Result<String, ProviderResponse> {
    config.kms
        .describe_key()
        .key_id(props.kms_ca_root_arn.clone())
        .send()
        .await
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to call KMS DescribeKey; {:?}", e))
                .build()
        )
        .and_then(|key_desc| key_desc
            .key_metadata()
            .ok_or(
                ProviderResponseBuilder::from_event_ref(event)
                    .status(ResponseStatus::Failed)
                    .reason(format!("KMS key metadata unavailable"))
                    .build()
            )
            .and_then(|key_metadata| key_metadata
                .description()
                .ok_or(
                    ProviderResponseBuilder::from_event_ref(event)
                        .status(ResponseStatus::Failed)
                        .reason(format!("cmk description is unavailable"))
                        .build()
                )
                .map(|descr| String::from(descr))
            )
        )
}

async fn verify_cert_signature <'c,'e,'p> (
    config: &'c ProviderConfig,
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'p CreateResourceProperties,
    cert: &Certificate
) -> Result<(), ProviderResponse> {
    config.kms
        .verify()
        .key_id(props.kms_ca_root_arn.clone())
        .message(kms::types::Blob::new(Bytes::from(cert.tbs_certificate.clone())))
        .message_type(kms::model::MessageType::Raw)
        .signature(kms::types::Blob::new(cert.signature_value.clone()))
        .signing_algorithm({
            use SignatureAlgorithmIdentifier::*;
            use kms::model::SigningAlgorithmSpec::*; 
            match cert.signature_algorithm {
                EcdsaWithSha256 => EcdsaSha256,
                EcdsaWithSha384 => EcdsaSha384,
            }
        })
        .send()
        .await
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to call KMS Verify; {:?}", e))
                .build()
        )
        .and_then(|verify_output|
            // TODO add certificate time valididty check
            if verify_output.signature_valid {
                Ok(())
            } else {
                Err(
                    ProviderResponseBuilder::from_event_ref(event)
                        .status(ResponseStatus::Failed)
                        .reason(format!("KMS Verify reported the certificate signature as invalid"))
                        .build()
                )
            }
        )
}

fn pem_encode_key(pkcs8_doc: &Document) -> String {
    info!("pem_encode_certificate");
    // PEM encode the full root certificate
    let enc = base64::encode(pkcs8_doc.as_ref());
    let mut pem = String::new();
    pem.push_str("-----BEGIN PRIVATE KEY-----");
    pem.push_str("\n");
    for (i, c) in enc.chars().enumerate() {
        if (i != 0) && (i % 64 == 0) { pem.push('\n'); }
        pem.push(c);
    }
    if &pem[pem.len()-1..] != "\n" { pem.push_str("\n"); }
    pem.push_str("-----END PRIVATE KEY-----");
    pem
}

fn pem_encode_certificate(ca_cert: &Certificate) -> String {
    info!("pem_encode_certificate");
    // PEM encode the full root certificate
    let enc = base64::encode(&Bytes::from(ca_cert)[..]);
    let mut pem = String::new();
    pem.push_str("-----BEGIN CERTIFICATE-----");
    pem.push_str("\n");
    for (i, c) in enc.chars().enumerate() {
        if (i != 0) && (i % 64 == 0) { pem.push('\n'); }
        pem.push(c);
    }
    if &pem[pem.len()-1..] != "\n" { pem.push_str("\n"); }
    pem.push_str("-----END CERTIFICATE-----");
    pem
}

fn create_random_serial_number<'config,'event>(
    config: &'config ProviderConfig,
    event: &'event ProviderRequestCreateEvent<CreateResourceProperties>
) -> Result<SerialNumber, ProviderResponse>{
    info!("create_random_serial_number");
    let mut sn_bytes = [0u8;19];
    config.rnd.fill(&mut sn_bytes).map_err(|e| 
        ProviderResponseBuilder::from_event_ref(event)
            .status(ResponseStatus::Failed)
            .reason(format!("Could not generate random serial number: {:?}", e))
            .build()
    )?;
    Ok(SerialNumber::new(sn_bytes))
}

fn get_resource_properties<'e>(
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>
) -> Result<&'e CreateResourceProperties, ProviderResponse> {
    info!("get_resource_properties");
    event.resource_properties.as_ref().ok_or_else(||
         ProviderResponseBuilder::from_event_ref(event)
            .status(ResponseStatus::Failed)
            .reason("Missing or invalid 'ResourceProperties' parameter".to_string())
            .build()
    )
}

fn get_current_datetime<'e>(
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>
) -> Result<OffsetDateTime, ProviderResponse> {
    info!("get_current_datetime");
    // get the current moment in time
    // NOTE: any non-zero .nanosecond() OffsetDateTime value will cause
    // yasna's UTCTime from_datetime() to fail and assert(panic)
    OffsetDateTime::now_utc()
        .replace_nanosecond(0) 
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("Could not get the current time: {:?}", e))
                .build())
}

async fn sign_certificate<'c,'e,'p,'s>(
    config: &'c ProviderConfig,
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'p CreateResourceProperties,
    tbs_cert: &'s ToBeSignedCertificate,
) -> Result<Certificate, ProviderResponse> {
    info!("sign_certificate");

    // Call KMS to sign the TBS portion of the root certificate
    config.kms
        .sign()
        .key_id(props.kms_ca_root_arn.clone())
        .message(kms::types::Blob::new(Bytes::from(tbs_cert)))
        .message_type(kms::model::MessageType::Raw)
        .signing_algorithm({
            use SignatureAlgorithmIdentifier::*;
            use kms::model::SigningAlgorithmSpec::*; 
            match tbs_cert.signature_algorithm {
                EcdsaWithSha256 => EcdsaSha256,
                EcdsaWithSha384 => EcdsaSha384,
            }
        })
        .send()
        .await
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to sign() on the x.509 certificate. props: {:?}; error:  {:?};",
                    &props,
                    e, 
                ))
                .build()
        )
        // Extract the signature bytes from the KMS sign() call response
        .and_then(|kms_sign_resp| kms_sign_resp
            .signature()
            .ok_or("signature unavailable!".to_string())
            .map(|blob| Bytes::copy_from_slice(blob.as_ref()))
            .map_err(|e|
                ProviderResponseBuilder::from_event_ref(event)
                    .status(ResponseStatus::Failed)
                    .reason(format!("While attempting to recover the signature returned from calling sign() on the x.509 root certificate for KMS CMK {}; {:?}",
                        &props.kms_ca_root_arn,
                        e, 
                    ))
                    .build()
            )
        )
        // Assemble the full root certificate, consisting of the TBS, signing algo, and the
        // signature from KMS
        .map(|signature|
            Certificate {
                tbs_certificate: tbs_cert.clone(),
                signature_algorithm: tbs_cert.signature_algorithm.clone(),
                signature_value: signature,
            }
        )
}
