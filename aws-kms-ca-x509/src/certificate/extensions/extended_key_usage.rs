use yasna::models::ObjectIdentifier;
use crate::certificate::extensions::Extension;

// OID: 2.5.29.37
// {
//      joint-iso-itu-t(2)
//      ds(5)
//      certificateExtension(29)
//      extKeyUsage(37)
// }
const OID_CE_EXT_KEY_USAGE : &'static [u64] = &[2,5,29,37];

// OID: 1.3.6.1.5.5.7.3.1
// {
//      iso(1)
//      identified-organization(3)
//      dod(6)
//      internet(1)
//      security(5)
//      mechanisms(5)
//      pkix(7)
//      kp(3)
//      id-kp-serverAuth(1)
// }
const OID_KP_SERVER_AUTH : &'static [u64] = &[1,3,6,1,5,5,7,3,1];

// OID: 1.3.6.1.5.5.7.3.2
// {
//      iso(1)
//      identified-organization(3)
//      dod(6)
//      internet(1)
//      security(5)
//      mechanisms(5)
//      pkix(7)
//      kp(3)
//      id-kp-clientAuth(2)
// }
const OID_KP_CLIENT_AUTH : &'static [u64] = &[1,3,6,1,5,5,7,3,2];

// OID: 1.3.6.1.5.5.7.3.3
// {
//      iso(1)
//      identified-organization(3)
//      dod(6)
//      internet(1)
//      security(5)
//      mechanisms(5)
//      pkix(7)
//      kp(3)
//      id-kp-codeSigning(3)
// }
const OID_KP_CODE_SIGNING : &'static [u64] = &[1,3,6,1,5,5,7,3,3];

// OID: 1.3.6.1.5.5.7.3.4
// {
//      iso(1)
//      identified-organization(3)
//      dod(6)
//      internet(1)
//      security(5)
//      mechanisms(5)
//      pkix(7)
//      kp(3)
//      id-kp-emailProtection(4)
// }
const OID_KP_EMAIL_PROTECTION : &'static [u64] = &[1,3,6,1,5,5,7,3,4];

// OID: 1.3.6.1.5.5.7.3.8
// {
//      iso(1)
//      identified-organization(3)
//      dod(6)
//      internet(1)
//      security(5)
//      mechanisms(5)
//      pkix(7)
//      kp(3)
//      id-kp-timeStamping(8)
// }
const OID_KP_TIME_STAMPING : &'static [u64] = &[1,3,6,1,5,5,7,3,8];

// OID: 1.3.6.1.5.5.7.3.9
// {
//      iso(1)
//      identified-organization(3)
//      dod(6)
//      internet(1)
//      security(5)
//      mechanisms(5)
//      pkix(7)
//      kp(3)
//      id-kp-OCSPSigning(9)
// }
const OID_KP_OCSP_SIGNING : &'static [u64] = &[1,3,6,1,5,5,7,3,9];

#[derive(Clone,Ord,PartialOrd,Eq,PartialEq,Debug)]
pub enum KeyPurpose {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

impl From<KeyPurpose> for ObjectIdentifier {
    fn from (kp: KeyPurpose) -> Self {
        use KeyPurpose::*;
        match kp {
            ServerAuth => ObjectIdentifier::from_slice(OID_KP_SERVER_AUTH),
            ClientAuth => ObjectIdentifier::from_slice(OID_KP_CLIENT_AUTH),
            CodeSigning => ObjectIdentifier::from_slice(OID_KP_CODE_SIGNING),
            EmailProtection => ObjectIdentifier::from_slice(OID_KP_EMAIL_PROTECTION),
            TimeStamping => ObjectIdentifier::from_slice(OID_KP_TIME_STAMPING),
            OcspSigning => ObjectIdentifier::from_slice(OID_KP_OCSP_SIGNING),
        }
    }
}

#[derive(Clone,Debug)]
pub struct ExtendedKeyUsage(pub Vec<KeyPurpose>); // TODO must have at least one value

impl From<ExtendedKeyUsage> for Extension {
    fn from (eku:ExtendedKeyUsage) -> Self {
        let extension_oid = ObjectIdentifier::from_slice(OID_CE_EXT_KEY_USAGE);
        let extension_value = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                for kp in eku.0 {
                    let oid = ObjectIdentifier::from(kp);
                    writer.next().write_oid(&oid)
                }
            })
        });
        Extension{
            oid: extension_oid,
            critical: false,
            value: extension_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ext_key_usage_with_server_auth_should_encode_correctly () {
        let expected = vec!(0x30,0x16, // SEQUENCE, 15 bytes
            0x06,0x03, // OID, 3 bytes
                0x55,0x1d,0x25, // encoding of OID(2.5.29.37)
            0x01,0x01, // BOOL, 1 byte
                 0x00, // TRUE (is critical)
            0x04,0x0c, // OCTET STRING 12 bytes
                 0x30, 0x0a, // SEQUENCE, 10 bytes
                    0x06,0x08, // OID, 8 bytes length
                        0x2b,0x06,0x01,0x05, // encoding of OID: 1.3.6.1.5.5.7.3.1
                        0x05,0x07,0x03,0x01);
        let eku = ExtendedKeyUsage(vec!(KeyPurpose::ServerAuth));
        let der = yasna::encode_der(&Extension::from(eku));

        assert_eq!(der, expected);
    }
    #[test]
    fn ext_key_usage_with_client_auth_should_encode_correctly () {
        let expected = vec!(0x30,0x16, // SEQUENCE, 15 bytes
            0x06,0x03, // OID, 3 bytes
                0x55,0x1d,0x25, // encoding of OID(2.5.29.37)
            0x01,0x01, // BOOL, 1 byte
                 0x00, // TRUE (is critical)
            0x04,0x0c, // OCTET STRING 12 bytes
                 0x30, 0x0a, // SEQUENCE, 10 bytes
                    0x06,0x08, // OID, 8 bytes length
                        0x2b,0x06,0x01,0x05, // encoding of OID: 1.3.6.1.5.5.7.3.2
                        0x05,0x07,0x03,0x02);
        let eku = ExtendedKeyUsage(vec!(KeyPurpose::ClientAuth));
        let der = yasna::encode_der(&Extension::from(eku));

        assert_eq!(der, expected);
    }

}
