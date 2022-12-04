use crate::ProviderConfig;
use crate::CreateResourceProperties;
use time::OffsetDateTime;
use bytes::Bytes;
use ring::rand::SecureRandom;
use ring::digest::{digest, SHA512_256};
use aws_custom_resource_provider_events::{
    ResponseStatus,
    ProviderResponse,
    ProviderResponseBuilder,
    ProviderRequestCreateEvent
};

use aws_kms_ca_x509::certificate::{
    Certificate,
    x509_version::X509Version,
    serial_number::SerialNumber,
    signature_algorithm_identifier::SignatureAlgorithmIdentifier,
    common_name::CommonName,
    to_be_signed_certificate::ToBeSignedCertificate,
    subject_public_key_info::SubjectPublicKeyInfo,
    extensions::{
        Extension,
        KeyUsage,
        KeyUsages,
        BasicConstraints,
        SubjectKeyIdentifier,
        AuthorityKeyIdentifier,
    }
};

use serde_json::{ Value };
use tracing::info;
use crate::pkey::get_kms_pub_key_bytes;
use aws_sdk_kms as kms;


/// Create the KMS-backed self-signed x.509 root certificate
///
/// 1. Retrieve the KMS CMK ARN from the resource properties.
///    The ARN should identify an AWS CMK with the following 
///    key-policy permissions granted to this Custom Resource
///    Provider: 
///    kms:GetPublicKey
///    kms:Sign
///    kms:UpdateKeyDescription
/// 2. Call KMS.getPublicKey() to retrieve the CMK's public key
/// 3. Assemble the To Be Signed (tbs) X.509 certificate using
///    the public key and and the CMK's ARN.
/// 4. Call KMS.sign() sending the tbs-certificate
/// 5. Assemble the signature result from #4 with the tbs-certificate
///    into the final X.509 certificate.
/// 6. PEM encode the final certificate.
/// 7. Verify the final PEM encoded certificate is less than 8kb
/// 8. Call KMS.updateKeyDescription() sending the final PEM encoded
///    certificate (PoC storage, replace later with S3 destination)
/// 9. Set the PEM encoded certificate value on the data object  
///
pub async fn create<'c,'e>(
    config: &'c ProviderConfig,
    event: &ProviderRequestCreateEvent<CreateResourceProperties>
) -> Result<ProviderResponse, ProviderResponse> {
    info!("create");
    let props = get_resource_properties(event)?; 
    let sn = create_random_serial_number(config, event)?;
    let now = get_current_datetime(event)?;
    let spki = get_kms_cmk_public_key(config, event, &props).await?;
    let skid = create_subject_key_id(&spki);
    let cn = CommonName::from(&props.kms_ca_root_arn);
    let tbs_cert = build_tbs_certificate(
        event,
        &props,
        &cn,
        &sn,
        &now,
        &spki,
        &skid
    )?;
    let ca_cert = sign_certificate(config, event, &props, &tbs_cert).await?;
    let pem = pem_encode_certificate(&ca_cert);

    assert_pem_len(pem.len(), event)?;

    update_kms_cmk_description(config, event, &props, &pem).await?;

    let data = vec![("kms_ca_root_pem", Value::from(pem))]
        .into_iter()
        .collect::<Value>();

    Ok(ProviderResponseBuilder::from_event_ref(event)
        .status(ResponseStatus::Success)
        .reason("Ok".to_string())
        .data(data)
        .build())
}

fn assert_pem_len<'e>(
    pem_len: usize,
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>
) -> Result<(), ProviderResponse> {
    info!("assert_pem_len");
    if pem_len > 8000 {
        return Err(
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("size of pem-encoded certificate, {} bytes, was larger that the expected size of 8000 bytes", pem_len))
                .build()) 
    }
    Ok(())
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

// compute an ID for it using a digest of the public key's bytes 
// This will become the identifier that all child certs will be referencing
fn create_subject_key_id(spki: &SubjectPublicKeyInfo) -> Vec<u8> {
    info!("create_subject_key_id");
    digest(&SHA512_256, &spki.public_key[..])
        .as_ref()
        .to_vec()
}

fn create_random_serial_number<'c,'e>(
    config: &'c ProviderConfig,
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>
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

async fn update_kms_cmk_description<'c,'e,'p,'s>(
    config: &'c ProviderConfig,
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'p CreateResourceProperties,
    pem: &'s str,
) -> Result<(), ProviderResponse> {
    info!("update_kms_cmk_description");
    config.kms
        .update_key_description()
        .key_id(props.kms_ca_root_arn.clone())
        .description(format!("X509 ROOT CA CERTIFICATE\n\n{}",pem))
        .send()
        .await
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to update the description the KMS CMK {}; {:?}",
                &props.kms_ca_root_arn,
                e,
            ))
            .build()
        )
        .map(|_| ())
}

// call out to KMS to retrieve the Public Key for the CMK ARN provided in
// the resource properties sent with the event.
async fn get_kms_cmk_public_key<'c,'e,'p>(
    config: &'c ProviderConfig,
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'p CreateResourceProperties
) -> Result<SubjectPublicKeyInfo, ProviderResponse> {
    info!("get_kms_cmk_public_key");
    config.kms
        .get_public_key()
        .key_id(props.kms_ca_root_arn.clone())
        .send()
        .await
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to retrieve the public key for KMS CMK {}; {:?}",
                &props.kms_ca_root_arn,
                e,
            ))
            .build()
        )
        .and_then(|kms_get_pub_key_response|
            get_kms_pub_key_bytes(kms_get_pub_key_response)
                .map_err(|e|
                    ProviderResponseBuilder::from_event_ref(event)
                        .status(ResponseStatus::Failed)
                        .reason(format!("While attempting to isolate the the public key bytes within the response from the KMS CMK {}; {:?}",
                        &props.kms_ca_root_arn,
                        e,
                    ))
                    .build()))
}

// construct the TBS portion of the root certificate
fn build_tbs_certificate <'e, 'p, 's> (
    event: &'e ProviderRequestCreateEvent<CreateResourceProperties>,
    props: &'p CreateResourceProperties,
    cn: &'s CommonName,
    sn: &'s SerialNumber,
    now: &'s OffsetDateTime,
    spki: &'s SubjectPublicKeyInfo,
    skid: &'s [u8] 
) -> Result<ToBeSignedCertificate, ProviderResponse> {
    info!("build_tbs_certificate");
    ToBeSignedCertificate::builder()
        .version(X509Version::V3)
        .serial(sn)
        .valid_days(*now, (365*7) as i64)
        .issuer_cn(cn)
        .subject_cn(cn)
        .subject_public_key_info(spki)
        .extension(Extension::from(BasicConstraints{
            ca: true,
            ..Default::default()
        }))
        .extension(Extension::from(KeyUsages(vec!(
            KeyUsage::KeyCertSign,
            KeyUsage::CrlSign,
        ))))
        .extension(Extension::from(SubjectKeyIdentifier::from(skid)))
        .extension(Extension::from(AuthorityKeyIdentifier::from(skid)))
        .build()
        .map_err(|e|
            ProviderResponseBuilder::from_event_ref(event)
                .status(ResponseStatus::Failed)
                .reason(format!("While attempting to construct the x.509 root certificate for the KMS CMK {}; {:?}",
                    &props.kms_ca_root_arn,
                    e, 
                ))
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
                .reason(format!("While attempting to sign() on the x.509 root certificate for KMS CMK {}; {:?}",
                    &props.kms_ca_root_arn,
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
