pub mod extensions;
pub mod key_algorithm_identifier;
pub mod subject_public_key_info;
pub mod validity;
pub mod signature_algorithm_identifier;
pub mod common_name;
pub mod relative_distinguished_name;
pub mod name;
pub mod x509_version;
pub mod serial_number;
pub mod to_be_signed_certificate;

use std::convert::{ TryFrom, From };
use bytes::Bytes;
use yasna::{
    ASN1ErrorKind,
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
};


pub struct Certificate {
    pub tbs_certificate: ToBeSignedCertificate,
    pub signature_algorithm: SignatureAlgorithmIdentifier,
    pub signature_value: Bytes,
}

impl From<Certificate> for Bytes {
    fn from(cert:Certificate) -> Bytes {
        Bytes::from(yasna::encode_der(&cert))
    }
}

impl TryFrom<Bytes> for Certificate {
    type Error = &'static str;
    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        yasna::parse_der(bytes.as_ref(), Certificate::decode_ber).map_err(|yasna_err| {
            match yasna_err.kind() {
                ASN1ErrorKind::Invalid => "invalid",
                ASN1ErrorKind::Eof => "eof",
                ASN1ErrorKind::Extra => "extra",
                ASN1ErrorKind::StackOverflow => "stack overflow",
                ASN1ErrorKind::IntegerOverflow => "integer overflow",
            }
        })        
    }
}

impl DEREncodable for Certificate {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.tbs_certificate.encode_der(writer.next());
            self.signature_algorithm.encode_der(writer.next());
            writer.next().write_bitvec_bytes(&self.signature_value[..],self.signature_value.len() * 8);
        });
    }
}

impl BERDecodable for Certificate {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let tbs_certificate = ToBeSignedCertificate::decode_ber(reader.next())?; 
            let signature_algorithm = SignatureAlgorithmIdentifier::decode_ber(reader.next())?;
            let (signature_value, _) = reader.next().read_bitvec_bytes()?; 
            return Ok(Certificate {
                tbs_certificate: tbs_certificate,
                signature_algorithm: signature_algorithm,
                signature_value: Bytes::from(signature_value),
            });
        })
    }
}

pub use extensions::*;
pub use key_algorithm_identifier::*;
pub use subject_public_key_info::*;
pub use validity::*;
pub use signature_algorithm_identifier::*;
pub use common_name::*;
pub use relative_distinguished_name::*;
pub use name::*;
pub use x509_version::*;
pub use serial_number::*;
pub use to_be_signed_certificate::*;

