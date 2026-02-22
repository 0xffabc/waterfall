pub struct ServerNameExtension {
    sni: String,
}

impl Into<Vec<u8>> for ServerNameExtension {
    fn into(self) -> Vec<u8> {
        let mut ext = vec![];

        let sni_bytes = self.sni.as_bytes();
        let sni_len = sni_bytes.len() as u16;

        ext.extend_from_slice(sni_bytes);
        ext.splice(0..0, sni_len.to_be_bytes());
        ext.insert(0, 0); /* DNS hostname  */

        /* Element length and list length */
        ext.splice(0..0, ext.len().to_be_bytes());
        ext.splice(0..0, ext.len().to_be_bytes());

        /* Server name */
        ext.splice(0..0, [0x00, 0x00]);

        ext
    }
}

pub struct OCSPRequestExtension();

impl Into<Vec<u8>> for OCSPRequestExtension {
    fn into(self) -> Vec<u8> {
        /*
         * Always constant
         *
         * 00 05 - Status request
         * 00 05 - 5 bytes of extension
         * 01 - OCSP
         * 00 00 - 0 bytes of responderID indo
         * 00 00 - 0 bytes of ext info
         */
        vec![00, 05, 00, 05, 01, 00, 00, 00, 00]
    }
}

#[repr(u16)]
pub enum NamedGroup {
    X25519 = 29,
    Secp256r1 = 23,
    Secp384r1 = 24,
    Secp521r1 = 25,
    X448 = 30,

    /* RFC 7919 */
    Ffdhe2048 = 256,
    Ffdhe3072 = 257,
    Ffdhe4096 = 258,
    Ffdhe6144 = 259,
    Ffdhe8192 = 260,
}

pub struct EllipticCurvesExtension {
    groups: Vec<NamedGroup>,
}

impl Into<Vec<u8>> for EllipticCurvesExtension {
    fn into(self) -> Vec<u8> {
        let mut vec = vec![];

        for group in self.groups {
            vec.extend_from_slice(&(group as u16).to_be_bytes());
        }

        /*
         * Curves list
         */
        vec.splice(0..0, (vec.len() as u16).to_be_bytes());

        /*
         * N bytes of elliptic curves extension
         */

        vec.splice(0..0, (vec.len() as u16).to_be_bytes());

        /*
         * Supported groups
         */

        vec.splice(0..0, [0x00, 0x0A]);

        vec
    }
}

pub struct ECPointFormatsExtension();

impl Into<Vec<u8>> for ECPointFormatsExtension {
    fn into(self) -> Vec<u8> {
        /*
         * Indicates that the client can only parse
         * uncompressed information from the server
         *
         * This extension will be required for waterfall,
         * since I'm not going to write my own
         * compressor implementation for tls 1.2 only
         */

        vec![0x00, 0x0B, 0x00, 0x02, 0x01, 0x00]
    }
}

#[repr(u16)]
pub enum SignatureAlgorithms {
    RsaPkscs1Sha256 = 1025,
    EcdsaSecp256r1Sha256 = 1027,
    RsaPkcs1Sha384 = 1281,
    EcdsaSecp384r1Sha384 = 1283,
    RsaPkcs1Sha512 = 1537,
    EcdsaSecp521r1Sha512 = 1539,
    RsaPkcs1Sha1 = 513,
    EcdsaSha1 = 515,
}

pub struct SignatureAlgorithmsExtension {
    algorithms: Vec<SignatureAlgorithms>,
}

impl Into<Vec<u8>> for SignatureAlgorithmsExtension {
    fn into(self) -> Vec<u8> {
        let mut vec = vec![];

        for algorithms in self.algorithms {
            vec.extend_from_slice(&(algorithms as u16).to_be_bytes());
        }

        /*
         * Signature algorithms, data
         */
        vec.splice(0..0, vec.len().to_be_bytes());
        vec.splice(0..0, vec.len().to_be_bytes());

        vec.splice(0..0, [0x00, 0x0d]);

        vec
    }
}

pub struct RenegotiationInfoExtension();

impl Into<Vec<u8>> for RenegotiationInfoExtension {
    fn into(self) -> Vec<u8> {
        /*
         * Prevents a type of attack performed with TLS renegotiation
         */

        vec![0xff, 0x01, 0x00, 0x01, 0x00]
    }
}

pub struct SignedCertificatetTimestampExtension();

impl Into<Vec<u8>> for SignedCertificatetTimestampExtension {
    fn into(self) -> Vec<u8> {
        /*
         * Provides permission for the server to return a signed certificate timestamp
         */

        vec![0x00, 0x12, 0x00, 0x00]
    }
}
