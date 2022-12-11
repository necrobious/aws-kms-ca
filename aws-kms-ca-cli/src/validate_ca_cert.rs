use std::error::Error;
use std::ops::Index;
use aws_sdk_kms as kms;
use clap::Parser;
use bytes::Bytes;
use regex::Regex;
use aws_kms_ca_x509::certificate::Certificate;
use aws_kms_ca_x509::certificate::signature_algorithm_identifier::SignatureAlgorithmIdentifier;
use base64;

#[derive(Parser, Debug)]
#[command(name = "validate_ca_cert")]
#[command(about = "Get an AWS KMS asym CMK's description, lookfor and parse an x.509 certificate, confirm the CN matches the CMK's ARN, send the cert back to the CMK for verification.", long_about = None)]
struct Cli {
    #[arg(
        long,
        short = 'k',
        value_name = "ARN",
        required = true,
        help = "Identifies the asymmetric CMK who's description contains an x.509 certificate to validate."
    )]
    key_id: String, 
   
}

async fn get_cmk_description (
    kms_client: &kms::Client,
    cmk_arn: impl Into<String>
) -> Result<String, String> {
    kms_client
        .describe_key()
        .key_id(cmk_arn)
        .send()
        .await
        .map_err(|e| e.to_string())
        .and_then(|key_desc| key_desc
            .key_metadata()
            .ok_or("key metadata unavailable".to_string())
            .and_then(|key_metadata| key_metadata
                .description()
                .ok_or("cmk description is unavailable".to_string())
                .map(|descr| String::from(descr))
            )
        )
}

async fn verify_cert_signature (
    kms_client: &kms::Client,
    cmk_arn: impl Into<String>,
    cert: &Certificate
) -> Result<bool, String> {
    kms_client
        .verify()
        .key_id(cmk_arn)
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
        .map_err(|e| e.to_string())
        .map(|verify_output| verify_output.signature_valid)
}

#[tokio::main]
async fn main () -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let aws_env_config = aws_config::load_from_env().await;
    let kms_client = kms::Client::new(&aws_env_config);

    let key_desc = get_cmk_description(&kms_client, &args.key_id).await?;

    let er = Regex::new(r"(?m)-----BEGIN CERTIFICATE-----[\n]+((([0-9A-Za-z/+]{64}|[0-9A-Za-z=/+]{1,63}=)[\n])+)+-----END CERTIFICATE-----[\n]*")
        .map_err(|e| Box::<dyn Error>::from(e))?;

    let (pem, b64) = er
        .captures(&key_desc)
        .map(|c| (
            String::from(c.index(0)),
            String::from(c.index(1).replace("\n",""))))
        .ok_or( Box::<dyn Error>::from("Could not find certificate in key description"))?;
    println!("{}", &pem);

    let der = base64::decode(&b64)
        .map_err(|e| Box::<dyn Error>::from(e))?;

    let cert = Certificate::try_from(Bytes::from(der))
        .map_err(|e| Box::<dyn Error>::from(e))?;

    let is_cert_valid = verify_cert_signature(&kms_client, &args.key_id, &cert).await?;
    println!("Certificate signature {} valid", if is_cert_valid { "is" } else { "is not" });

    Ok(())
}
