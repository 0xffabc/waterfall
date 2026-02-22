#[repr(u8)]
pub enum ChipherSuite {
    TlsEcdheRsaWithChacha20Poly1305Sha256,
    TlsEcdheEcdsaWithChacha20Poly1305Sha256,
    TlsEcdheRsaWithAes128GcmSha256,
    TlsEcdheRsaWithAes256GcmSha384,
    TlsEcdheEcdsaWithAes128GcmSha256,
    TlsEcdheEcdsaWithAes256GcmSha384,
    TlsEcdheRsaWithAes128CbcSha,
    TlsEcdheEcdsaWithAes128CbcSha,
    TlsEcdheRsaWithAes256CbcSha,
    TlsEcdheEcdsaWithAes256CbcSha,
    TlsRsaWithAes128GcmSha256,
    TlsRsaWithAes256GcmSha384,
    TlsRsaWithAes128CbcSha,
    TlsRsaWithAes256CbcSha,
    TlsEcdheRsaWith3desEdeCbcSha,
    TlsRsaWith3desEdeCbcSha,
}

pub enum Extensions {
    ServerName,
    StatusRequest,
    EllipticCurves,
    ECPointFormats,
    SignatureAlgorithms,
    RenegotiationInfo,
    SignedCertificateTimestamp,
}

pub struct ClientHello {
    pub record_len: u16,
    pub ch_len: u16,
    pub random: [u8; 32],
    pub session_id: u8,
    pub cipher_suites: Vec<ChipherSuite>,
    pub extensions: Vec<Extensions>,
}
