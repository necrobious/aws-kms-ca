use crate::certificate::relative_distinguished_name::RelativeDistinguishedName;
use yasna::{DERWriter, DEREncodable};

#[derive(Clone)]
pub struct Name {
    pub rdn_sequence: Vec<RelativeDistinguishedName>
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
    fn name_should_encode_correctly () {
        let expected = vec!(0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x0c,0x05,0x68,0x65,0x6c,0x6c,0x6f);
        let cn = CommonName("hello".to_string());
        let rdn = RelativeDistinguishedName { common_name: cn };
        let name = Name { rdn_sequence: vec!(rdn) };
        let der = yasna::encode_der(&name);
        assert_eq!(der, expected);
    }
}
