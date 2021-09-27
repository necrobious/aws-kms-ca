use crate::certificate::relative_distinguished_name::RelativeDistinguishedName;
use yasna::{
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
};


#[derive(Clone, Debug, PartialEq,)]
pub struct Name {
    pub rdn_sequence: Vec<RelativeDistinguishedName>
}

impl BERDecodable for Name {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let rdn_sequence = reader.collect_sequence_of(|inner| {
            RelativeDistinguishedName::decode_ber(inner)
        })?;
        return Ok(Name{ rdn_sequence: rdn_sequence }) 
    }
}

impl DEREncodable for Name {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for rdn in self.rdn_sequence.iter() {
                rdn.encode_der(writer.next());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::certificate::common_name::CommonName;
    use super::*;

    #[test]
    fn rdn_should_decode_correctly () {

        let asserted = vec!(0x30,0x10, // SEQUENCE OF, 16 bytes
            0x31,0x0e, // SET, 14 bytes
                0x30,0x0c, // SEQUENCE, 12 bytes
                    0x06,0x03, // OID, 3 bytes
                        0x55,0x04,0x03, // encoding of OID(2.5.4.3)
                    0x0c,0x05, // UTF8String, 5 bytes
                        0x68,0x65,0x6c,0x6c,0x6f); // "hello", in ut8 bytes

        let cn = CommonName("hello".to_string());
        let rdn = RelativeDistinguishedName { common_name: cn };
        let name = Name { rdn_sequence: vec!(rdn) }; 
        let expected = Ok(name);
        let actual = yasna::parse_der(&asserted, Name::decode_ber);
        assert_eq!(actual, expected);
    }
 
    #[test]
    fn name_should_encode_correctly () {
        let expected = vec!(0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x0c,0x05,0x68,0x65,0x6c,0x6c,0x6f);
        let cn = CommonName("hello".to_string());
        let rdn = RelativeDistinguishedName { common_name: cn };
        let name = Name { rdn_sequence: vec!(rdn) };
        let der = yasna::encode_der(&name);
        assert_eq!(der, expected);
    }
}
