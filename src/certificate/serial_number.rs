use yasna::{DERWriter, DEREncodable};
use num_bigint::BigUint;

#[derive(Clone)]
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
}
