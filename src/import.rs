use url::Url;

use crate::models::OtpAuthUri;

/// Parse an `otpauth://totp/...` URI into components.
///
/// Format:
/// `otpauth://totp/{label}?secret={BASE32}&issuer={ISSUER}&algorithm={ALGO}&digits={D}&period={P}`
pub fn parse_otpauth_uri(uri_str: &str) -> Result<OtpAuthUri, String> {
    let url = Url::parse(uri_str).map_err(|e| format!("Invalid URL: {}", e))?;

    if url.scheme() != "otpauth" {
        return Err("Not an otpauth:// URI".into());
    }

    if url.host_str() != Some("totp") {
        return Err(format!(
            "Expected otpauth://totp/..., got otpauth://{}/",
            url.host_str().unwrap_or("unknown")
        ));
    }

    // Label is the path without leading slash
    let label = url.path().trim_start_matches('/').to_string();
    if label.is_empty() {
        return Err("Missing label in otpauth URI".into());
    }

    let mut secret = None;
    let mut issuer: Option<String> = None;
    let mut algorithm = "SHA1".to_string();
    let mut digits = 6;
    let mut period = 30;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.to_string()),
            "issuer" => issuer = Some(value.to_string()),
            "algorithm" => algorithm = value.to_uppercase(),
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| format!("Invalid digits: {}", value))?;
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| format!("Invalid period: {}", value))?;
            }
            _ => {} // ignore unknown params
        }
    }

    let secret_base32 = secret.ok_or("Missing 'secret' parameter in otpauth URI")?;

    // Validate base32 by trying to decode
    totp_rs::Secret::Encoded(secret_base32.clone())
        .to_bytes()
        .map_err(|e| format!("Invalid base32 secret: {}", e))?;

    Ok(OtpAuthUri {
        label,
        issuer,
        secret_base32,
        algorithm,
        digits,
        period,
    })
}

/// Try to extract an otpauth URI from arbitrary text.
pub fn extract_uri(text: &str) -> Option<OtpAuthUri> {
    let trimmed = text.trim();

    if trimmed.starts_with("otpauth://") {
        return parse_otpauth_uri(trimmed).ok();
    }

    for word in trimmed.split_whitespace() {
        if word.starts_with("otpauth://") {
            return parse_otpauth_uri(word).ok();
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_google_style_uri() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.label, "Example:alice@google.com");
        assert_eq!(parsed.issuer, Some("Example".into()));
        assert_eq!(parsed.secret_base32, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_parse_minimal_uri() {
        let uri = "otpauth://totp/MyApp?secret=JBSWY3DPEHPK3PXP";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.label, "MyApp");
        assert_eq!(parsed.algorithm, "SHA1");
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
    }

    #[test]
    fn test_reject_non_otpauth() {
        assert!(parse_otpauth_uri("https://example.com").is_err());
        assert!(parse_otpauth_uri("otpauth://hotp/foo?secret=ABC").is_err());
    }
}
