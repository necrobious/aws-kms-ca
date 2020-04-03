use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, DEREncodable};

#[derive(Clone)]
pub struct CommonName(pub String);

impl DEREncodable for CommonName {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            // OID: 2.5.4.32
            // {
            //      joint-iso-itu-t(2)
            //      ds(5)
            //      attributeType(4)
            //      commonName(3)
            // }
            let cn_oid = ObjectIdentifier::from_slice(&[2,5,4,3]);
            writer.next().write_oid(&cn_oid);
            writer.next().write_utf8_string(&self.0);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_name_attr_should_encode_correctly () {
        let expected = vec!(0x30,0x0c, // SEQUENCE, 13 bytes
            0x06,0x03, // OID, 3 bytes
                0x55,0x04,0x03, // encoding of OID(2.5.4.3)
            0x0c,0x05, // UTF8String, 5 bytes
                0x68,0x65,0x6c,0x6c,0x6f); // "hello", in ut8 bytes
        let der = yasna::encode_der(&CommonName("hello".to_string()));
        assert_eq!(der, expected);
    }
}
