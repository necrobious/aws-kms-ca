use crate::certificate::common_name::{
    CommonName,
};
use yasna::{
    ASN1Error,
    ASN1ErrorKind,
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
    models::ObjectIdentifier,
};

#[cfg(feature = "tracing")]
use tracing::{debug};

/* TODO: we need implement more distingushed names: 
 * from:  https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
 * RFC5288 § 4.1.2.4:
 *   Implementations of this specification MUST
 *   be prepared to receive the following standard attribute types in
 *   issuer and subject (Section 4.1.2.6) names:
 *
 *    * country,
 *    * organization,
 *    * organizational unit,
 *    * distinguished name qualifier,
 *    * state or province name,
 *    * common name (e.g., "Susan Housley"), and
 *    * serial number.
 *
 *   In addition, implementations of this specification SHOULD be prepared
 *   to receive the following standard attribute types in issuer and
 *   subject names:
 *
 *    * locality,
 *    * title,
 *    * surname,
 *    * given name,
 *    * initials,
 *    * pseudonym, and
 *    * generation qualifier (e.g., "Jr.", "3rd", or "IV").
 */
#[derive(Clone, Debug, PartialEq,)]
pub struct RelativeDistinguishedNameBuilder {
    common_name: Option<CommonName>
}

impl RelativeDistinguishedNameBuilder {
    pub fn common_name(mut self, cn: CommonName) -> RelativeDistinguishedNameBuilder {
        self.common_name = Some(cn);
        self
    }

    pub fn build(self) -> Result<RelativeDistinguishedName, String> {
        let rdn = RelativeDistinguishedName {
          common_name: self.common_name.ok_or("missing common name".to_string())?, 
        };
        Ok(rdn)
    }
}

impl Default for RelativeDistinguishedNameBuilder {
    fn default() -> Self {
        RelativeDistinguishedNameBuilder {
            common_name: None 
        }
    }
}


#[derive(Clone, Debug, PartialEq,)]
pub struct RelativeDistinguishedName {
    pub common_name: CommonName
}

enum AttributeTypeAndValue {
    CN(CommonName)
}

impl RelativeDistinguishedName {
    pub fn builder() -> RelativeDistinguishedNameBuilder {
        RelativeDistinguishedNameBuilder::default()
    }
}

impl BERDecodable for RelativeDistinguishedName {
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "RelativeDistinguishedName::decode_ber"))]
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        #[cfg(feature = "tracing")]
        debug!("parsing relative distinguished name");
         
        //  RelativeDistinguishedName ::=
        //     SET SIZE (1..MAX) OF AttributeTypeAndValue
        //  AttributeTypeAndValue ::= SEQUENCE {
        //     type     AttributeType,
        //     value    AttributeValue }
        //  AttributeType ::= OBJECT IDENTIFIER
        //  AttributeValue ::= ANY -- DEFINED BY AttributeType

        let atvs:Vec<AttributeTypeAndValue> = reader.collect_set_of(|inner| {
            inner.read_sequence(|atv| {
                let cn_oid = ObjectIdentifier::from_slice(&[2,5,4,3]);
                // oid determins which values to read next
                let oid = atv.next().read_oid();

                // cn
                if oid == Ok(cn_oid) {
                    #[cfg(feature = "tracing")]
                    debug!("parsing common name");
                    let cn = atv.next().read_utf8string()?;
                    return Ok(AttributeTypeAndValue::CN(CommonName(cn))) 
                }

                return Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            })
        })?;

        let mut builder = RelativeDistinguishedName::builder();

        for atv in atvs {
            match atv {
                AttributeTypeAndValue::CN(cn) => {
                    builder = builder.common_name(cn);
                },
            }
        }

        return builder
            .build()
            .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid)); // TODO: surface error message

    }
}


impl DEREncodable for RelativeDistinguishedName {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_set_of(|writer| {
            self.common_name.encode_der(writer.next());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdn_should_decode_correctly () {
        let asserted = vec!(0x31,0x0e,// SET, 14 bytes
            0x30,0x0c, // SEQUENCE, 12 bytes
                0x06,0x03, // OID, 3 bytes
                    0x55,0x04,0x03, // encoding of OID(2.5.4.3)
                0x0c,0x05, // UTF8String, 5 bytes
                    0x68,0x65,0x6c,0x6c,0x6f); // "hello", in ut8 bytes
        let cn = CommonName("hello".to_string());
        let rdn = RelativeDistinguishedName { common_name: cn };
        let expected = Ok(rdn);
        let actual = yasna::parse_der(&asserted, RelativeDistinguishedName::decode_ber);
        assert_eq!(actual, expected);
    }
   
    #[test]
    fn a_valid_but_unsupported_oid_should_fail () {
        let asserted = vec!(0x31,0x13,// SET, 19 bytes
            0x30,0x11, // SEQUENCE, 17 bytes
                0x06,0x08, // OID, 8 bytes
                    0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04, // encoding of OID(1.2.840.10045.4.3.4)
                0x0c,0x05, // UTF8String, 5 bytes
                    0x68,0x65,0x6c,0x6c,0x6f); // "hello", in ut8 bytes
        let expected = Err(ASN1Error::new(ASN1ErrorKind::Invalid)); 

        let actual = yasna::parse_der(&asserted, RelativeDistinguishedName::decode_ber);
        assert_eq!(actual, expected);
    }

    #[test]
    fn rdn_should_encode_correctly () {
        let expected = vec!(0x31,0x0e,// SET, 14 bytes
            0x30,0x0c, // SEQUENCE, 12 bytes
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
