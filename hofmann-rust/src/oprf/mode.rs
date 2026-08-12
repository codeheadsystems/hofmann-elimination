/// RFC 9497 §3.1 protocol mode.
///
/// The mode byte goes into the context string and therefore into every
/// domain-separation tag derived from it. A suite built for the wrong mode does
/// not fail — it computes a different function under a different tag set, and
/// the mistake surfaces as an interop failure or an unverifiable stored hash.
/// [`OprfCipherSuite::assert_mode`](crate::oprf::OprfCipherSuite::assert_mode)
/// exists so it fails instead.
///
/// **One key must not serve two modes.** The same secret under two tag sets is
/// two different functions, RFC 9497 §7.2.3's static Diffie-Hellman budget is
/// per-key, and POPRF exposes an inversion oracle where the other modes expose a
/// multiplication one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OprfMode {
    /// Base mode (0x00). No proof. What OPAQUE and the plain OPRF use.
    Oprf,
    /// Verifiable OPRF (0x01). The server proves it used its committed key.
    Voprf,
    /// Partially-oblivious OPRF (0x02). VOPRF plus a public input.
    Poprf,
}

impl OprfMode {
    /// The byte that goes into the context string.
    pub fn value(&self) -> u8 {
        match self {
            OprfMode::Oprf => 0x00,
            OprfMode::Voprf => 0x01,
            OprfMode::Poprf => 0x02,
        }
    }

    /// The mode's name, for error messages.
    pub fn name(&self) -> &'static str {
        match self {
            OprfMode::Oprf => "OPRF",
            OprfMode::Voprf => "VOPRF",
            OprfMode::Poprf => "POPRF",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_bytes_match_rfc_9497() {
        assert_eq!(OprfMode::Oprf.value(), 0x00);
        assert_eq!(OprfMode::Voprf.value(), 0x01);
        assert_eq!(OprfMode::Poprf.value(), 0x02);
    }
}
