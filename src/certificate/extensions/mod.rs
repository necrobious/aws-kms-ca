pub mod basic_constraints;
pub mod key_usage;
pub mod authority_key_identifier;
pub mod subject_key_identifier;
pub mod extended_key_usage;
pub mod subject_alternative_name;

use yasna::{
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
    models::ObjectIdentifier,
};

#[cfg(feature = "tracing")]
use tracing::{debug};

#[derive(Clone, Debug, PartialEq,)]
pub struct Extension {
    oid: ObjectIdentifier,
    critical: bool,
    value: Vec<u8>,
}

impl BERDecodable for Extension {
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "Extension::decode_ber"))]
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        #[cfg(feature = "tracing")]
        debug!("parsing extension");
        reader.read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            let critical = reader.next().read_bool()?;
            let value = reader.next().read_bytes()?;
            Ok(Extension {
                oid: oid,
                critical: critical,
                value: value,
            })
        })
    }
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
