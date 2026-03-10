//! SPI trait for out-of-band identity verification during account recovery.

/// Defines how your application sends and verifies recovery challenges.
///
/// Implement this trait to integrate your preferred out-of-band identity
/// verification mechanism (email codes, SMS OTP, TOTP, admin approval, etc.).
///
/// # Security
///
/// - [`send_challenge`](RecoveryChallenger::send_challenge) **must not** reveal
///   whether the credential exists. If the credential is unknown, either silently
///   succeed (recommended) or send a generic "if this account exists..." message.
/// - [`verify_response`](RecoveryChallenger::verify_response) should use
///   constant-time comparison to prevent timing attacks on challenge codes.
///
/// # Example
///
/// ```rust,ignore
/// struct EmailChallenger { /* ... */ }
///
/// impl RecoveryChallenger for EmailChallenger {
///     fn send_challenge(&self, credential_identifier: &[u8]) -> Result<(), String> {
///         let email = std::str::from_utf8(credential_identifier)
///             .map_err(|e| e.to_string())?;
///         let code = generate_secure_code();
///         self.store_code(email, code.clone());
///         self.email_service.send(email, &format!("Code: {}", code));
///         Ok(())
///     }
///
///     fn verify_response(
///         &self,
///         credential_identifier: &[u8],
///         challenge_response: &str,
///     ) -> bool {
///         let email = std::str::from_utf8(credential_identifier).ok();
///         email.and_then(|e| self.remove_code(e))
///             .map(|stored| subtle::ConstantTimeEq::ct_eq(
///                 stored.as_bytes(), challenge_response.as_bytes()
///             ).into())
///             .unwrap_or(false)
///     }
/// }
/// ```
pub trait RecoveryChallenger: Send + Sync {
    /// Sends an out-of-band challenge to the user identified by `credential_identifier`.
    ///
    /// Returns `Ok(())` on success, or `Err` with a description if the challenge
    /// could not be sent (e.g. email service unavailable). The error message
    /// **must not** reveal whether the credential exists.
    fn send_challenge(&self, credential_identifier: &[u8]) -> Result<(), String>;

    /// Verifies the user's response to a previously sent challenge.
    ///
    /// Returns `true` if the response is valid and the user's identity is confirmed.
    fn verify_response(
        &self,
        credential_identifier: &[u8],
        challenge_response: &str,
    ) -> bool;
}
