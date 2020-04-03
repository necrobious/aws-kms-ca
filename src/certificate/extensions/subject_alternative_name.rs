use yasna::Tag;
use yasna::models::ObjectIdentifier;
use crate::certificate::extensions::Extension;
use std::net::IpAddr;

// OID: 2.5.29.37
// {
//      joint-iso-itu-t(2)
//      ds(5)
//      certificateExtension(29)
//      subjectAltName(17)
// }
const OID_CE_SUBJECT_ALT_NAME : &'static [u64] = &[2,5,29,17];

#[derive(Clone)]
pub enum GeneralName {
    DnsName(String),
    IpAddress(IpAddr),
}

#[derive(Clone)]
pub struct SubjectAlternativeName(pub Vec<GeneralName>);

impl From<SubjectAlternativeName> for Extension {
    fn from (san:SubjectAlternativeName) -> Self {
        let extension_oid = ObjectIdentifier::from_slice(OID_CE_SUBJECT_ALT_NAME);
        let extension_value = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                for name in san.0 {
                    match name {
                        GeneralName::DnsName(dns_name) => {
                            writer.next().write_tagged_implicit(Tag::context(2), |writer| {
                                writer.write_ia5_string(&dns_name)
                            })
                        },
                        GeneralName::IpAddress(IpAddr::V4(v4_addr)) => {
                            writer.next().write_tagged_implicit(Tag::context(7), |writer| {
                                writer.write_bytes(&v4_addr.octets())
                            })
                        },
                        GeneralName::IpAddress(IpAddr::V6(v6_addr)) => {
                            writer.next().write_tagged_implicit(Tag::context(7), |writer| {
                                writer.write_bytes(&v6_addr.octets())
                            })
                        },
                    }
                }
            })
        });
        Extension{
            oid: extension_oid,
            critical: false,
            value: extension_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr,Ipv6Addr};

    #[test]
    fn subject_alt_name_with_dns_name_should_encode_correctly () {
        let expected = vec!(
            0x30,0x12, // SEQUENCE, 18 bytes -- subjectAltName extension extension
                0x06, 0x03, // OID, 3 bytes subjectAltName extension ID
                    0x55, 0x1d,0x11, // encoding of OID: 2.5.29.17
                0x01, 0x01, // BOOL, 1 byte -- is extension critical
                    0x00, // FALSE
                0x04, 0x08, // OCTET STRING, 8 bytes -- ext params, for SAN, RFC 5280 § 4.2.1.6
                    0x30, 0x06, // SEQUENCE, 6 bytes -- SAN GeneralNames
                    0x82, 0x04, // [2] TAGGED, 4 bytes -- DNSName
                        0x74, 0x65, 0x73, 0x74 // DNS Name, "test"
        );
        let san = SubjectAlternativeName(vec!(GeneralName::DnsName("test".to_string())));
        let der = yasna::encode_der(&Extension::from(san));

        assert_eq!(der, expected);
    }

    #[test]
    fn subject_alt_name_with_ipv4_addr_should_encode_correctly () {
        let expected = vec!(
            0x30,0x12, // SEQUENCE, 18 bytes -- subjectAltName extension extension
                0x06, 0x03, // OID, 3 bytes subjectAltName extension ID
                    0x55, 0x1d,0x11, // encoding of OID: 2.5.29.17
                0x01, 0x01, // BOOL, 1 byte -- is extension critical
                    0x00, // FALSE
                0x04, 0x08, // OCTET STRING, 8 bytes -- ext params, for SAN, RFC 5280 § 4.2.1.6
                    0x30, 0x06, // SEQUENCE, 6 bytes -- SAN GeneralNames
                    0x87, 0x04, // [7] TAGGED, 4 bytes -- IP ADDRESS
                        0x7f, 0x00, 0x00, 0x01 // IPv4 Address, 4 bytes
        );
        //    [48, 18, 6, 3, 85, 29, 17, 1, 1, 0, 4, 8, 48, 6, 130, 4, 116, 101, 115, 116]
        let san = SubjectAlternativeName(vec!(GeneralName::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))));
        let der = yasna::encode_der(&Extension::from(san));

        assert_eq!(der, expected);
    }

    #[test]
    fn subject_alt_name_with_ipv6_addr_should_encode_correctly () {
        let expected = vec!(
            0x30,0x1e, // SEQUENCE, 30 bytes -- subjectAltName extension extension
                0x06, 0x03, // OID, 3 bytes subjectAltName extension ID
                    0x55, 0x1d,0x11, // encoding of OID: 2.5.29.17
                0x01, 0x01, // BOOL, 1 byte -- is extension critical
                    0x00, // FALSE
                0x04, 0x14, // OCTET STRING, 20 bytes -- ext params, for SAN, RFC 5280 § 4.2.1.6
                    0x30, 0x12, // SEQUENCE, 6 bytes -- SAN GeneralNames
                    0x87, 0x10, // [7] TAGGED, 4bytes -- IP ADDRESS
                        0x00, 0x00, 0x00, 0x00, // IPv6 address, 16 bytes
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
        );
        //    [48, 18, 6, 3, 85, 29, 17, 1, 1, 0, 4, 8, 48, 6, 130, 4, 116, 101, 115, 116]
        let san = SubjectAlternativeName(vec!(GeneralName::IpAddress(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))));
        let der = yasna::encode_der(&Extension::from(san));

        assert_eq!(der, expected);
    }

}
