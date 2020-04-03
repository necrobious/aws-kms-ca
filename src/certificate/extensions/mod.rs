pub mod basic_constraints;
pub mod key_usage;
pub mod authority_key_identifier;
pub mod subject_key_identifier;
pub mod extended_key_usage;
pub mod subject_alternative_name;

use yasna::{DERWriter, DEREncodable};
use yasna::models::ObjectIdentifier;

#[derive(Clone)]
pub struct Extension {
    oid: ObjectIdentifier,
    critical: bool,
    value: Vec<u8>,
}

impl DEREncodable for Extension {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&self.oid); // extnID
            writer.next().write_bool(self.critical); // is critical
            writer.next().write_bytes(&self.value); // extnValue
        });
    }
}

pub use basic_constraints::*;
pub use key_usage::*;
pub use authority_key_identifier::*;
pub use subject_key_identifier::*;
pub use extended_key_usage::*;
pub use subject_alternative_name::*;
