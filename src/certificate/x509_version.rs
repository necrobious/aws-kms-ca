use yasna::{
    ASN1Error,
    ASN1ErrorKind,
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
    Tag
};


#[derive(Clone, Debug, PartialEq,)]
pub enum X509Version {
    V3
}

impl DEREncodable for X509Version {
    fn encode_der(&self, writer: DERWriter) {
        match self {
            X509Version::V3 =>
            writer.write_tagged(Tag::context(0), |writer| {
                writer.write_u8(0x02)
            })
        }
    }
}

impl BERDecodable for X509Version {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let ver = reader.read_tagged(Tag::context(0), |reader| {
            reader.read_u8()
        })?;
        if ver == 0x02 {
            return Ok(X509Version::V3)
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn x509_v3_should_encode_correctly () {
        let expected = vec!(
            0xa0,0x03, // [0] EXPLICIT  TAG
                0x02,0x01, // INTEGER, 1 byte
                    0x02); // integer value of 2
        let der = yasna::encode_der(&X509Version::V3);
        assert_eq!(der, expected);
    }

    #[test]
    fn x509_v3_should_decode_correctly() {
        let asserted = vec!(
            0xa0,0x03, // [0] EXPLICIT  TAG
                0x02,0x01, // INTEGER, 1 byte
                    0x02); // integer value of 2
        let expected = Ok(X509Version::V3); 

        let actual = yasna::parse_der(&asserted, X509Version::decode_ber);
        assert_eq!(actual, expected);
    }

    #[test]
    fn x509_v2_should_should_fail() {
        let asserted = vec!(
            0xa0,0x03, // [0] EXPLICIT  TAG
                0x02,0x01, // INTEGER, 1 byte
                    0x01); // integer value of 2
        let expected = Err(ASN1Error::new(ASN1ErrorKind::Invalid)); 

        let actual = yasna::parse_der(&asserted, X509Version::decode_ber);
        assert_eq!(actual, expected);
    }


}
