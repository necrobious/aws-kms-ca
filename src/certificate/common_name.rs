use yasna::models::ObjectIdentifier;
use yasna::{
    ASN1Error,
    ASN1ErrorKind,
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
};


#[derive(Clone, Debug, PartialEq,)]
pub struct CommonName(pub String);

impl BERDecodable for CommonName {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let cn_oid = ObjectIdentifier::from_slice(&[2,5,4,3]);
            let oid = reader.next().read_oid()?;
            if oid != cn_oid {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            let cn = reader.next().read_utf8string()?;
            return Ok(CommonName(cn))
        })
    }
}

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
    fn common_name_attr_should_decode_correctly () {
        let asserted = vec!(0x30,0x0c, // sequence, 13 bytes
            0x06,0x03, // oid, 3 bytes
                0x55,0x04,0x03, // encoding of oid(2.5.4.3)
            0x0c,0x05, // utf8string, 5 bytes
                0x68,0x65,0x6c,0x6c,0x6f); // "hello", in ut8 bytes
        let expected = Ok(CommonName("hello".to_string()));
        let actual = yasna::parse_der(&asserted, CommonName::decode_ber);
        assert_eq!(actual, expected);
    }


    #[test]
    fn common_name_attr_should_encode_correctly () {
        let expected = vec!(0x30,0x0c, // sequence, 13 bytes
            0x06,0x03, // oid, 3 bytes
                0x55,0x04,0x03, // encoding of oid(2.5.4.3)
            0x0c,0x05, // utf8string, 5 bytes
                0x68,0x65,0x6c,0x6c,0x6f); // "hello", in ut8 bytes
        let der = yasna::encode_der(&CommonName("hello".to_string()));
        assert_eq!(der, expected);
    }

}
