use std::error::Error;
use clap::Parser;
use aws_sdk_kms as kms;

fn get_p384_pkey <'a> (public_key: &'a[u8]) -> Result<&'a[u8],String> {
    match public_key {
        [0x30,0x76, // SEQUENCE, 118 bytes
            0x30,0x10, // SEQUENCE, 16 bytes
                0x06,0x07, // OID, 7 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,// encoding of OID(1.2.840.10045.2.1) RFC 5480 2.1.1 - ecPublicKey 
                0x06,0x05, // OID, 5 Bytes
                    0x2b,0x81,0x04,0x00,0x22, // encoding of OID(1.3.132.0.34) RFC 5480 2.1.1.1 - secp384r1
            0x03,0x62,0x00, // BIT STRING, 98 bytes, 0 unused
                pkey @ ..] => Ok(pkey), // 97 byte public key
        _ => Err("unexpected ECC_NIST_P384 prelude".to_string())
    }
}

fn get_p256_pkey <'a> (public_key: &'a[u8]) -> Result<&'a[u8],String> {
    match public_key {
        [0x30,0x59, // SEQUENCE, 89 bytes
            0x30,0x13, // SEQUENCE, 19 bytes
                0x06,0x07, // OID, 7 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,// encoding of OID(1.2.840.10045.2.1) RFC 5480 2.1.1 - ecPublicKey 
                0x06,0x08, // OID, 8 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07, // encoding of OID(1.2.840.10045.3.1.7) RFC 5480 2.1.1.1 - secp256r1
            0x03,0x42,0x00, // BIT STRING, 66 bytes, 0 unused
                pkey @ ..] => Ok(pkey), // 65 byte public key
        _ => Err("unexpected ECC_NIST_P256 prelude".to_string())
    }
}

fn get_pub_key_bytes <'a> (res: &'a kms::output::GetPublicKeyOutput) -> Result<&'a [u8], String> {
    use kms::model::KeySpec::*;
    match (res.public_key(), res.key_spec()) {
        (Some(blob), Some(spec)) if *spec == EccNistP384 => {
            get_p384_pkey(blob.as_ref())//.map(|pk| Bytes::from(pk.clone()))
        },
        (Some(blob), Some(spec)) if *spec == EccNistP256 => {
            get_p256_pkey(blob.as_ref())//.map(|pk| Bytes::from(pk))
        },
        _ => {
            Err("Could not determine Public Key from spec".to_string())
        }

    }
}

#[derive(Parser, Debug)]
#[command(name = "get_cmk_pkey")]
#[command(about = "Get an AWS KMS asym CMK's Public Key.", long_about = None)]
struct Cli {
    #[arg(
        long,
        short = 'k',
        value_name = "ARN",
        required = true,
        help = "Identifies the asymmetric CMK that includes the public key."
    )]
    key_id: String, 
} 

#[tokio::main]
async fn main () -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let aws_env_config = aws_config::load_from_env().await;
    let kms_client = kms::Client::new(&aws_env_config);
    let kms_get_pkey_resp = kms_client
        .get_public_key()
        .key_id(args.key_id)
        .send()
        .await?;

    let pkey = get_pub_key_bytes(&kms_get_pkey_resp)? 
            .iter()
            .map(|b| format!("{:02x?}",b))
            .collect::<Vec<String>>()
            .join(":");

    println!("{}",pkey);
    Ok(())
}
