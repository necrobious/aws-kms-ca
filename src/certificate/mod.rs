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

use std::convert::From;
use bytes::Bytes;
use yasna::{DERWriter, DEREncodable};

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

impl DEREncodable for Certificate {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.tbs_certificate.encode_der(writer.next());
            self.signature_algorithm.encode_der(writer.next());
            writer.next().write_bitvec_bytes(&self.signature_value[..],self.signature_value.len() * 8);
        });
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

