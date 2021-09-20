use rusoto_core::region::Region;
use rusoto_kms::{GetPublicKeyRequest, GetPublicKeyResponse, KmsClient, Kms};
use std::default::Default;
use clap::{Arg, App};
use std::str::FromStr;
use bytes::Bytes;

const SPEC_ECC_NIST_P384: &'static str = "ECC_NIST_P384";
const SPEC_ECC_NIST_P256: &'static str = "ECC_NIST_P256";

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
                pkey @ ..] => Ok(pkey), // 97 byte public key
        _ => Err("unexpected ECC_NIST_P256 prelude".to_string())
    }
}


fn get_pub_key_bytes (res:GetPublicKeyResponse) -> Result<Bytes, String> {
    match (res.public_key, res.customer_master_key_spec) {
        (Some(bytes), Some(spec)) if spec == SPEC_ECC_NIST_P384 => {
            get_p384_pkey(&bytes[..]).map(|pk| bytes.slice_ref(pk))
        },
        (Some(bytes), Some(spec)) if spec == SPEC_ECC_NIST_P256 => {
            get_p256_pkey(&bytes[..]).map(|pk| bytes.slice_ref(pk))
        },
        _ => {
            Err("Could not determine Public Key from spec".to_string())
        }
    }
}


fn is_aws_region (input:String) -> Result<(), String> {
    Region::from_str(input.as_ref()).map(|_| ()).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main () {
    let matches = App::new("get_cmk_pkey")
        .about("Get an AWS KMS asym CMK's Public Key")
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
        .get_matches();

    let region = matches
        .value_of("region")
        .and_then(|r| Region::from_str(r).ok())
        .unwrap();

    let key_id = matches
        .value_of("key_id")
        .map(|s| s.to_string() )
        .unwrap();

    let kms_client = KmsClient::new(region);
    let get_pub_key_request = GetPublicKeyRequest{
        key_id,
        ..Default::default()
    };

    match kms_client.get_public_key(get_pub_key_request).await {
        Ok(get_pub_key_response) => {
            let res = get_pub_key_bytes(get_pub_key_response)
                .map(|pk| pk.iter().map(|b| format!("{:02x?}",b)).collect::<Vec<String>>().join(":"))
                .map_or_else(|e| format!("Err: {}",e), |v| format!("public key: {}",v));
            println!("{}",res);
        },
        Err(err) => {
            println!("Error: {:?}", err);
        }
    }

}
