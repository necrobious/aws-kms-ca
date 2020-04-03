use crate::certificate::common_name::CommonName;
use yasna::{DERWriter, DEREncodable};

#[derive(Clone)]
pub struct RelativeDistinguishedName {
    pub common_name: CommonName
}

impl DEREncodable for RelativeDistinguishedName {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_set(|writer| {
            self.common_name.encode_der(writer.next());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdn_should_encode_correctly () {
        let expected = vec!(0x31,0x0e,// SET, 15 bytes
            0x30,0x0c, // SEQUENCE, 13 bytes
                0x06,0x03, // OID, 3 bytes
                    0x55,0x04,0x03, // encoding of OID(2.5.4.3)
                0x0c,0x05, // UTF8String, 5 bytes
                    0x68,0x65,0x6c,0x6c,0x6f); // "hello", in ut8 bytes
        let cn = CommonName("hello".to_string());
        let rdn = RelativeDistinguishedName { common_name: cn };
        let der = yasna::encode_der(&rdn);
        assert_eq!(der, expected);
    }
}
