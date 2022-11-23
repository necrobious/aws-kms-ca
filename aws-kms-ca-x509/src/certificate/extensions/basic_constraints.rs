use yasna::models::ObjectIdentifier;
use crate::certificate::extensions::Extension;
use core::default::Default;

#[derive(Clone, Debug)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_length_constraint: Option<usize>,
}

impl Default for BasicConstraints {
    fn default() -> Self {
        BasicConstraints {
            ca: false,
            path_length_constraint: None
        }
    }
}

impl From<BasicConstraints> for Extension {
    fn from(bc:BasicConstraints) -> Self {
        // OID: 2.5.29.19
        // {
        //      joint-iso-itu-t(2)
        //      ds(5)
        //      certificateExtension(29)
        //      basicConstraints(19)
        //  }
        let extension_oid = ObjectIdentifier::from_slice(&[2,5,29,19]);
        let extension_value = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_bool(bc.ca);
                if bc.path_length_constraint.is_some() {
                    writer.next().write_u32(
                        bc.path_length_constraint.unwrap() as u32
                    );
                }
            });
        });
        Extension{
            oid: extension_oid,
            critical: true,
            value: extension_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_constraints_should_encode_correctly () {
        let expected = vec!(0x30,0x12, // SEQUENCE, 18 bytes length (extension SEQUENCE)
            0x06,0x03, // OID, 3 bytes length
                0x55,0x1d,0x13, // encoding of OID(2.5.29.19)
            0x01,0x01, // BOOL, 1 byte length
                 0xff, // TRUE (is critical)
            0x04,0x08, // OCTET STRING 8 bytes length
                 0x30,0x06, // SEQUENCE, 6 bytes length (basic constraints SEQUENCE)
                    0x01,0x01, // BOOL, 1 byte length (is CA)
                        0x0ff, // TRUE
                    0x02,0x01, // INTEGER, 1 byte length (pathLenConstraint)
                        0x01); // encoded value of 1

        let bc = BasicConstraints {
            ca: true,
            path_length_constraint: Some(1),
        };

        let der = yasna::encode_der(&Extension::from(bc));

        assert_eq!(der, expected);
    }
}
