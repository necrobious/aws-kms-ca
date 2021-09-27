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
use crate::certificate::x509_version::X509Version;
use crate::certificate::serial_number::SerialNumber;
use crate::certificate::key_algorithm_identifier::KeyAlgorithmIdentifier;
use crate::certificate::signature_algorithm_identifier::SignatureAlgorithmIdentifier;
use crate::certificate::name::Name;
use crate::certificate::validity::Validity;
use crate::certificate::relative_distinguished_name::RelativeDistinguishedName;
use crate::certificate::common_name::CommonName;
use crate::certificate::subject_public_key_info::SubjectPublicKeyInfo;
use crate::certificate::extensions::Extension;
use std::convert::From;
use chrono::prelude::*;
use bytes::Bytes;

#[derive(Clone)]
pub struct ToBeSignedCertificateBuilder {
    version: Option<X509Version>,
    serial: Option<SerialNumber>,
    signature_algorithm: Option<SignatureAlgorithmIdentifier>,
    issuer: Option<Name>,
    validity: Option<Validity>,
    subject: Option<Name>,
    subject_public_key_info: Option<SubjectPublicKeyInfo>,
    extensions: Vec<Extension>,
}

impl ToBeSignedCertificateBuilder {
    pub fn version(mut self, version: X509Version) -> Self {
        self.version = Some(version);
        self
    }

    pub fn serial(mut self, serial: SerialNumber) -> Self {
        self.serial = Some(serial);
        self
    }

    pub fn signature_algorithm(mut self, signature_algorithm: SignatureAlgorithmIdentifier) -> Self {
        self.signature_algorithm = Some(signature_algorithm);
        self
    }

    pub fn issuer(mut self, issuer: Name) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn issuer_cn(mut self, issuer: CommonName) -> Self {
        self.issuer = Some(Name { rdn_sequence: vec!( RelativeDistinguishedName {
            common_name: issuer
        })});
        self
    }



    pub fn validity(mut self, validity: Validity) -> Self {
        self.validity = Some(validity);
        self
    }

    pub fn valid_days(mut self, from: DateTime<Utc>, days_valid: i64) -> Self {
        self.validity =
            match (
                from.with_nanosecond(0),
                from.checked_add_signed(chrono::Duration::days(days_valid))
                    .and_then(|dt| dt.with_nanosecond(0))) {
                (Some(nb),Some(na)) => Some(Validity {not_before: nb, not_after: na}),
                _ => None
            };
        self
    }

    pub fn subject(mut self, subject: Name) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn subject_cn(mut self, subject: CommonName) -> Self {
        self.subject = Some(Name { rdn_sequence: vec!( RelativeDistinguishedName {
            common_name: subject
        })});
        self
    }

    pub fn subject_public_key_info(mut self, subject_public_key_info: SubjectPublicKeyInfo) -> Self {
        if self.signature_algorithm.is_none() {
            self.signature_algorithm = match subject_public_key_info.algorithm {
                KeyAlgorithmIdentifier::P256 =>
                    Some(SignatureAlgorithmIdentifier::EcdsaWithSha256),
                KeyAlgorithmIdentifier::P384 =>
                    Some(SignatureAlgorithmIdentifier::EcdsaWithSha384),
            }
        }
        self.subject_public_key_info = Some(subject_public_key_info);
        self
    }


    pub fn extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    pub fn build(self) -> Result<ToBeSignedCertificate,String> {
        let tbs = ToBeSignedCertificate {
            version: self.version.ok_or("missing version".to_string())?,
            serial: self.serial.ok_or("missing serial".to_string())?,
            signature_algorithm: self.signature_algorithm.ok_or("missing signature_algorithm".to_string())?,
            issuer: self.issuer.ok_or("missing issuer".to_string())?,
            validity: self.validity.ok_or("missing validity".to_string())?,
            subject: self.subject.ok_or("missing subject".to_string())?,
            subject_public_key_info: self.subject_public_key_info.ok_or("missing subject_public_key_info".to_string())?,
            extensions: self.extensions,
        };
        Ok(tbs)
    }
}

impl Default for ToBeSignedCertificateBuilder {
    fn default() -> Self {
        ToBeSignedCertificateBuilder {
            version: None,
            serial: None,
            signature_algorithm: None,
            issuer: None,
            validity: None,
            subject: None,
            subject_public_key_info: None,
            extensions: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct ToBeSignedCertificate {
    pub version: X509Version,
    pub serial: SerialNumber,
    pub signature_algorithm: SignatureAlgorithmIdentifier,
    pub issuer: Name ,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub extensions: Vec<Extension>,
}

impl From<ToBeSignedCertificate> for Bytes {
    fn from(tbs:ToBeSignedCertificate) -> Bytes {
        Bytes::from(yasna::encode_der(&tbs))
    }
}

impl ToBeSignedCertificate {
    pub fn builder() -> ToBeSignedCertificateBuilder {
        ToBeSignedCertificateBuilder::default()
    }
}

impl DEREncodable for ToBeSignedCertificate {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.version.encode_der(writer.next());
            self.serial.encode_der(writer.next());
            self.signature_algorithm.encode_der(writer.next());
            self.issuer.encode_der(writer.next());
            self.validity.encode_der(writer.next());
            self.subject.encode_der(writer.next());
            self.subject_public_key_info.encode_der(writer.next());
            if self.extensions.len() > 0 {
                writer.next().write_tagged(Tag::context(3), |writer| {
                    writer.write_sequence(|writer| {
                        for ext in self.extensions.iter() {
                            ext.encode_der(writer.next());
                        }
                    })
                })
            }
        });
    }
}

impl BERDecodable for ToBeSignedCertificate {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let builder = ToBeSignedCertificate::builder();
            builder
                .version(X509Version::decode_ber(reader.next())?)
                .serial(SerialNumber::decode_ber(reader.next())?)
                .signature_algorithm(SignatureAlgorithmIdentifier::decode_ber(reader.next())?)
                .issuer(Name::decode_ber(reader.next())?)
                .validity(Validity::decode_ber(reader.next())?)
                .subject(Name::decode_ber(reader.next())?)
                .subject_public_key_info(SubjectPublicKeyInfo::decode_ber(reader.next())?)
                // TODO: add parsing of extensions
                .build()
                .map_err(|_|ASN1Error::new(ASN1ErrorKind::Invalid))
        })
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::relative_distinguished_name::RelativeDistinguishedName;
    use crate::certificate::common_name::CommonName;
    use crate::certificate::extensions::basic_constraints::BasicConstraints;
    use crate::certificate::key_algorithm_identifier::KeyAlgorithmIdentifier;

    #[test]
    fn to_be_signed_certificate_should_encode_correctly () {
        let expected = vec!(
            0x30, // SEQUENCE -- To-be-signed X509 Certificate.
            0x81, // because length is is more than 127 bytes,
                  // bit 7 of the Length field is set to 1 and bits 6 through 0 specify the number
                  // of additional bytes used to identify the content length (1 byte in ths case)
            0xf2, // of 242 bytes length

                0xa0, // [0] EXPLICIT TAG
                0x03, // of 3 bytes length
                    0x02, // INTEGER -- X.509 Version value
                    0x01, // of 1 byte length
                    0x02, // X.509 version 3 encoded value. https://tools.ietf.org/html/rfc5280#section-4.1.2.1

                0x02, // INTEGER -- Certificate Serial Number
                0x01, // of 1 byte length
                0x01, // encoded serial number value of 1. https://tools.ietf.org/html/rfc5280#section-4.1.2.2

                0x30, // SEQUENCE -- Signature Algorithm Identifier
                0x0a, // of 10 bytes length
                    0x06, // OID -- OID(1.2.840.10045.4.3.2) -- ecdsa with sha-256
                    0x08, // of 8 bytes length
                    0x2a,0x86,0x48,0xce, // encoding of OID(1.2.840.10045.4.3.2)
                    0x3d,0x04,0x03,0x02, // https://tools.ietf.org/html/rfc7427#appendix-A.3.2

                0x30, // SEQUENCE -- Issuer -- Name
                0x15, // of 21 bytes length
                    0x31, // -- SET -- Issuer -- RelativeDistinguishedName
                    0x13, // of 19 bytes length
                        0x30, // SEQUENCE -- Issuer -- AttributeTypeAndValue
                        0x11, // of 17 bytes length
                            0x06, // -- OID -- OID(2.5.4.3) -- common name
                            0x03, // of 3 bytes length
                            0x55,0x04,0x03, //  encoding of OID(2.5.4.3)

                            0x0c, // UTF8String
                            0x0a, // of 10 bytes length
                            0x54,0x65,0x73,0x74, // UTF-8 encoding of string:
                            0x69,0x6e,0x67,0x20, // 'Testing CA'
                            0x43,0x41,

                0x30, // SEQUENCE -- Validity
                0x1e, // of 30 bytes length
                    0x17, // UTCTime
                    0x0d, // of 13 bytes length
                        0x32,0x30, // yy -- ASCII '20'
                        0x30,0x39, // MM -- ASCII '09'
                        0x30,0x39, // dd -- ASCII '09'
                        0x30,0x31, // HH -- ASCII '01'
                        0x34,0x36, // mm -- ASCII '46'
                        0x34,0x30, // ss -- ASCII '40'
                        0x5a,      // tx -- ASCII 'Z'
                    0x17, // UTCTime
                    0x0d, // of 13 bytes length
                        0x32,0x31, // yy -- ASCII '21'
                        0x30,0x39, // MM -- ASCII '09'
                        0x30,0x39, // dd -- ASCII '09'
                        0x30,0x31, // HH -- ASCII '01'
                        0x34,0x36, // mm -- ASCII '46'
                        0x34,0x30, // ss -- ASCII '40'
                        0x5a,      // tx -- ASCII 'Z'

                0x30,// SEQUENCE -- Subject -- Name
                0x15,// of 21 bytes length
                    0x31, // SET -- Subject -- RelativeDistinguishedName
                    0x13, // of 19 bytes length
                        0x30, // SEQUENCE -- Subject -- AttributeTypeAndValue
                        0x11, // of 17 bytes length

                            0x06, // -- OID -- OID(2.5.4.3) -- common name
                            0x03, // of 3 bytes length
                            0x55,0x04,0x03, //  encoding of OID(2.5.4.3)

                            0x0c, // UTF8String
                            0x0a, // of 10 bytes length
                            0x54,0x65,0x73,0x74, // UTF-8 encoding of string:
                            0x69,0x6e,0x67,0x20, // 'Testing CA'
                            0x43,0x41,

                0x30, // SEQUENCE -- SubjectPublicKeyInfo
                0x76, // of 118 bytes length
                    0x30, // SEQUENCE -- P-384 public key algorithm
                    0x10, // of 16 bytes length
                        0x06, // OID -- OID(1.2.840.10045.2.1) -- ecPublicKey
                        0x07, // of 7 bytes length
                        0x2a,0x86,0x48,0xce, // encoding of OID(1.2.840.10045.2.1)
                        0x3d,0x02,0x01,

                        0x06, // OID -- OID(1.3.132.0.34) -- ansip384r1
                        0x05, // of 5 bytes length
                        0x2b,0x81,0x04,0x00,0x22, // encoding of OID(1.3.132.0.34)

                    0x03, // BIT STRING
                    0x62, // of 98 bytes length
                    0x00, // with 0 unused bits
                        0x04,0x74,0xf4,0x86,0x1a,0x09,0xe2,0x5a, // P-384 Public Key
                        0xff,0x27,0xd3,0x02,0x71,0x72,0x56,0x33, // 97 bytes
                        0x7a,0xce,0x0b,0x92,0x00,0xb7,0xb0,0x7a,
                        0x91,0x07,0x91,0xf3,0x1e,0xd8,0xc9,0xe1,
                        0x32,0x4e,0x0e,0x0f,0x3b,0x84,0x00,0x33,
                        0xb0,0x9d,0x1a,0x92,0xf0,0x20,0xa1,0x05,
                        0xe8,0xdf,0xe1,0x2d,0xb5,0x08,0xdb,0x10,
                        0xe1,0x17,0x1b,0xdc,0x35,0xbf,0x55,0xe6,
                        0x98,0xb5,0x93,0xe2,0x5d,0xd7,0x05,0x8c,
                        0x04,0x1a,0xfb,0x3f,0x2b,0x24,0xac,0x31,
                        0x33,0xc6,0x7f,0xab,0xab,0x05,0x4c,0xda,
                        0xed,0xbd,0x40,0x85,0x4a,0x90,0xc8,0x4f,
                        0x9c,

                0xa3, // [3] EXPLICIT TAG
                0x16, // of 22 bytes length
                    0x30, // SEQUENCE extensions
                    0x14, // of 18 bytes length
                        0x30, // SEQUENCE basicConstraints extension
                        0x12, // of 18 bytes length
                            0x06, // OID -- OID(2.5.29.19) -- basicConstraints
                            0x03, // of 3 bytes length
                            0x55,0x1d,0x13, // encoding of OID(2.5.29.19)

                            0x01, // BOOL -- is extention critical
                            0x01, // of 1 byte length
                            0xff, // encoding of TRUE

                            0x04, // OCTET STRING -- Extention Value
                            0x08,
                                0x30, // SEQUENCE -- Basic Constraints value
                                0x06, // of 6 bytes length
                                    0x01, // BOOL -- is CA
                                    0x01, // of 1 byte length
                                    0xff, // encoding of TRUE

                                    0x02,  // INTEGER -- pathLenConstraint
                                    0x01,  // of 1 byte length
                                    0x01); // encoding ov the value of '1'


        let tbs_cert = ToBeSignedCertificate {
            version: X509Version::V3,
            serial: SerialNumber::new([
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x01]),
            signature_algorithm: SignatureAlgorithmIdentifier::EcdsaWithSha256,
            issuer: Name {
                rdn_sequence: vec!(
                    RelativeDistinguishedName {
                        common_name: CommonName("Testing CA".to_string())
                    }
                )
            },
            validity: Validity {
                not_before: Utc.ymd(2020, 9, 9).and_hms(1, 46, 40),
                not_after: Utc.ymd(2021, 9, 9).and_hms(1, 46, 40)
            },
            subject: Name {
                rdn_sequence: vec!(
                    RelativeDistinguishedName {
                        common_name: CommonName("Testing CA".to_string())
                    }
                )
            },
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: KeyAlgorithmIdentifier::P384,
                public_key: vec!(
                    0x04,0x74,0xf4,0x86,0x1a,0x09,0xe2,0x5a, // P-384 Public Key, 97 bytes
                    0xff,0x27,0xd3,0x02,0x71,0x72,0x56,0x33,
                    0x7a,0xce,0x0b,0x92,0x00,0xb7,0xb0,0x7a,
                    0x91,0x07,0x91,0xf3,0x1e,0xd8,0xc9,0xe1,
                    0x32,0x4e,0x0e,0x0f,0x3b,0x84,0x00,0x33,
                    0xb0,0x9d,0x1a,0x92,0xf0,0x20,0xa1,0x05,
                    0xe8,0xdf,0xe1,0x2d,0xb5,0x08,0xdb,0x10,
                    0xe1,0x17,0x1b,0xdc,0x35,0xbf,0x55,0xe6,
                    0x98,0xb5,0x93,0xe2,0x5d,0xd7,0x05,0x8c,
                    0x04,0x1a,0xfb,0x3f,0x2b,0x24,0xac,0x31,
                    0x33,0xc6,0x7f,0xab,0xab,0x05,0x4c,0xda,
                    0xed,0xbd,0x40,0x85,0x4a,0x90,0xc8,0x4f,
                    0x9c
                ),
            },
            extensions: vec!(
                Extension::from(BasicConstraints {
                    ca: true,
                    path_length_constraint: Some(1),
                })

            ),
        };

        let tbs_bytes = yasna::encode_der(&tbs_cert);

        assert_eq!(expected,tbs_bytes);
    }

}
