use yasna::{Tag, DERWriter, DEREncodable};

#[derive(Clone)]
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
}
