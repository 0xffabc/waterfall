use crate::l5::tls12::extensions::{
    ECPointFormatsExtension, EllipticCurvesExtension, OCSPRequestExtension,
    RenegotiationInfoExtension, ServerNameExtension, SignatureAlgorithmsExtension,
    SignedCertificatetTimestampExtension,
};

pub mod extensions;

#[repr(u16)]
#[derive(Clone)]
pub enum ChipherSuite {
    TlsEcdheRsaWithChacha20Poly1305Sha256 = 52392,
    TlsEcdheEcdsaWithChacha20Poly1305Sha256 = 52393,
    TlsEcdheRsaWithAes128GcmSha256 = 49199,
    TlsEcdheRsaWithAes256GcmSha384 = 49200,
    TlsEcdheEcdsaWithAes128GcmSha256 = 49195,
    TlsEcdheEcdsaWithAes256GcmSha384 = 49196,
    TlsEcdheRsaWithAes128CbcSha = 49171,
    TlsEcdheEcdsaWithAes128CbcSha = 49161,
    TlsEcdheRsaWithAes256CbcSha = 49172,
    TlsEcdheEcdsaWithAes256CbcSha = 49162,
    TlsRsaWithAes128GcmSha256 = 156,
    TlsRsaWithAes256GcmSha384 = 157,
    TlsRsaWithAes128CbcSha = 47,
    TlsRsaWithAes256CbcSha = 53,
    TlsEcdheRsaWith3desEdeCbcSha = 49170,
    TlsRsaWith3desEdeCbcSha = 10,
}

pub enum Extensions {
    ServerName(ServerNameExtension),
    StatusRequest(OCSPRequestExtension),
    EllipticCurves(EllipticCurvesExtension),
    ECPointFormats(ECPointFormatsExtension),
    SignatureAlgorithms(SignatureAlgorithmsExtension),
    RenegotiationInfo(RenegotiationInfoExtension),
    SignedCertificateTimestamp(SignedCertificatetTimestampExtension),
}

pub struct ClientHello {
    pub record_len: u16,
    pub ch_len: u16,
    pub random: [u8; 32],
    pub session_id: u8,
    pub cipher_suites: Vec<ChipherSuite>,
    pub extensions: Vec<Extensions>,
}

impl Into<Vec<u8>> for ClientHello {
    fn into(self) -> Vec<u8> {
        let mut vec = vec![];

        for extension in self.extensions {
            let ext: Vec<u8> = match extension {
                Extensions::ECPointFormats(ext) => ext.into(),
                Extensions::EllipticCurves(ext) => ext.into(),
                Extensions::RenegotiationInfo(ext) => ext.into(),
                Extensions::ServerName(ext) => ext.into(),
                Extensions::SignatureAlgorithms(ext) => ext.into(),
                Extensions::SignedCertificateTimestamp(ext) => ext.into(),
                Extensions::StatusRequest(ext) => ext.into(),
            };

            vec.extend_from_slice(&ext);
        }

        vec.splice(0..0, vec.len().to_be_bytes());

        /*
         * No compression
         * (weakens the security of data)
         */

        vec.splice(0..0, [01, 00]);

        let suites_len = (self.cipher_suites.len() * 2) as u16;

        for cipher_suite in self.cipher_suites {
            vec.splice(0..0, (cipher_suite as u16).to_be_bytes());
        }

        /*
         * Cipher suites length
         */

        vec.splice(0..0, suites_len.to_be_bytes());

        /*
         * Session id to reuse the old TLS session
         *
         * Perform whenever possible
         */

        vec.insert(0, self.session_id);

        /*
         * Client random
         */

        vec.splice(0..0, self.random);

        /*
         * Client version (1.2)
         */

        vec.splice(0..0, [0x03, 0x03]);

        /*
         * Handshake header
         */

        vec.splice(0..0, vec.len().to_be_bytes());
        vec.splice(0..0, [01, 00]);

        /*
         * TLS Record header
         */

        let len = vec.len() as u32;

        vec.splice(0..0, [(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        vec.splice(0..0, [0x16, 0x03, 0x01]);

        vec
    }
}
