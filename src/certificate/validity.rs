use yasna::models::UTCTime;
use chrono::prelude::*;
use yasna::{
    ASN1Result,
    DERWriter,
    DEREncodable,
    BERReader,
    BERDecodable,
};

#[cfg(feature = "tracing")]
use tracing::{debug};

#[derive(Clone, Debug, PartialEq,)]
pub struct Validity {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}


impl BERDecodable for Validity {
    #[cfg_attr(feature = "tracing", tracing::instrument(name = "Validity::decode_ber"))]
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        #[cfg(feature = "tracing")]
        debug!("parsing validity");
        reader.read_sequence(|reader| {
            let nb = *reader.next().read_utctime()?.datetime();
            let na = *reader.next().read_utctime()?.datetime();
            Ok(Validity {
                not_before: nb,
                not_after: na,
            })
        })
    }
}


impl DEREncodable for Validity {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            let nb = UTCTime::from_datetime(&self.not_before);
            let na = UTCTime::from_datetime(&self.not_after);
            writer.next().write_utctime(&nb);
            writer.next().write_utctime(&na);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validity_should_decode_correctly () {
        let asserted = vec!(0x30,0x1e, // SEQUENCE, 30 bytes
            0x17,0x0d, // UTCTime type, len 13 bytes
                0x32,0x30, // yy - 20 in ASCII
                0x30,0x39, // MM - 09 in ASCII
                0x30,0x39, // dd - 09 in ASCII
                0x30,0x31, // HH - 01 in ASCII
                0x34,0x36, // mm - 46 in ASCII
                0x34,0x30, // ss - 40 in ASCII
                0x5a,      // tz - Z  in ASCII
            0x17,0x0d, // UTCTime type, len 13 bytes
                0x32,0x31, // yy - 21 in ASCII
                0x30,0x39, // MM - 09 in ASCII
                0x30,0x39, // dd - 09 in ASCII
                0x30,0x31, // HH - 01 in ASCII
                0x34,0x36, // mm - 46 in ASCII
                0x34,0x30, // ss - 40 in ASCII
                0x5a);     // tz - Z
        let then = Utc.ymd(2020, 9, 9).and_hms(1, 46, 40);
        let when = Utc.ymd(2021, 9, 9).and_hms(1, 46, 40);

        let expected = Ok(Validity { not_before: then, not_after: when });
        let actual = yasna::parse_der(&asserted, Validity::decode_ber);
        assert_eq!(actual, expected);
    }

    #[test]
    fn validity_should_encode_correctly () {
        let expected = vec!(0x30,0x1e, // SEQUENCE, 30 bytes
            0x17,0x0d, // UTCTime type, len 13 bytes
                0x32,0x30, // yy - 20 in ASCII
                0x30,0x39, // MM - 09 in ASCII
                0x30,0x39, // dd - 09 in ASCII
                0x30,0x31, // HH - 01 in ASCII
                0x34,0x36, // mm - 46 in ASCII
                0x34,0x30, // ss - 40 in ASCII
                0x5a,      // tz - Z  in ASCII
            0x17,0x0d, // UTCTime type, len 13 bytes
                0x32,0x31, // yy - 21 in ASCII
                0x30,0x39, // MM - 09 in ASCII
                0x30,0x39, // dd - 09 in ASCII
                0x30,0x31, // HH - 01 in ASCII
                0x34,0x36, // mm - 46 in ASCII
                0x34,0x30, // ss - 40 in ASCII
                0x5a);     // tz - Z
        let then = Utc.ymd(2020, 9, 9).and_hms(1, 46, 40);
        let when = Utc.ymd(2021, 9, 9).and_hms(1, 46, 40);

        let validity = Validity { not_before: then, not_after: when };
        let der = yasna::encode_der(&validity);
        assert_eq!(der, expected);
    }
}
