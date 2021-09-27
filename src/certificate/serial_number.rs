use yasna::{
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
};

use num_bigint::BigUint;

#[derive(Clone, Debug, PartialEq,)]
pub struct SerialNumber(pub BigUint);

impl SerialNumber {
    pub fn new(bytes:[u8;19]) -> SerialNumber {
        SerialNumber(BigUint::from_bytes_be(&bytes))
    }
}

impl DEREncodable for SerialNumber {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_biguint(&self.0);
    }
}

impl BERDecodable for SerialNumber {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let sn_biguint = reader.read_biguint()?;
        return Ok(SerialNumber(sn_biguint))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serial_number_should_encode_correctly () {
        let expected = vec!(0x02,0x01,0x01);
        let bytes:[u8;19] = [
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x01
        ];
        let serial = SerialNumber::new(bytes);
        let der = yasna::encode_der(&serial);
        assert_eq!(der, expected);
    }

    #[test]
    fn serial_number_should_decode_correctly () {
       // DER encoding of the OID(1.2.840.10045.4.3.4)
        let asserted:[u8;3] = [0x02,0x01,0x01];

        let expected = Ok(SerialNumber::new([
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x01
        ])); 

        let actual = yasna::parse_der(&asserted, SerialNumber::decode_ber);
        assert_eq!(actual, expected);
    }

}
