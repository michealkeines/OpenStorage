//! Single source of truth for `HTTP status → PluginError` mapping.
//!
//! Every HTTP plugin uses `HttpClient`, which uses this. There is no other
//! mapping table in the codebase, by design.

use crate::PluginError;

use super::ratelimit::RateLimitInfo;

/// Map a non-2xx HTTP response into a typed `PluginError`. The detector has
/// already had its chance to extract a rate-limit signal; if it returned
/// one, we use it. Otherwise we fall back to status-based defaults.
pub fn status_to_plugin_error(
    status: u16,
    body: &[u8],
    rate_limit: Option<RateLimitInfo>,
) -> PluginError {
    if let Some(rl) = rate_limit {
        return PluginError::RateLimited {
            retry_after: rl.retry_after,
            scope: rl.scope,
        };
    }
    let body_text = std::str::from_utf8(body).unwrap_or("<binary>").to_string();
    match status {
        404 => PluginError::Plugin("not found".into()),
        401 | 403 => PluginError::AuthFailure,
        413 | 415 | 422 => PluginError::Plugin(format!("client error {status}: {body_text}")),
        // Other 4xx are not retryable; surface as Plugin.
        400..=499 => PluginError::Plugin(format!("client error {status}: {body_text}")),
        // 5xx without a Retry-After hint: transient, retry with exponential backoff.
        500..=599 => PluginError::Unavailable(format!("server error {status}: {body_text}")),
        _ => PluginError::Plugin(format!("unexpected status {status}: {body_text}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RateLimitScope;
    use std::time::Duration;

    #[test]
    fn rate_limit_passthrough() {
        let err = status_to_plugin_error(
            429,
            b"",
            Some(RateLimitInfo {
                retry_after: Duration::from_secs(5),
                scope: RateLimitScope::Global,
            }),
        );
        assert!(matches!(err, PluginError::RateLimited { .. }));
    }

    #[test]
    fn _404_is_not_found() {
        assert!(matches!(
            status_to_plugin_error(404, b"", None),
            PluginError::Plugin(_)
        ));
    }

    #[test]
    fn _401_is_auth_failure() {
        assert!(matches!(
            status_to_plugin_error(401, b"", None),
            PluginError::AuthFailure
        ));
    }

    #[test]
    fn _500_is_unavailable() {
        assert!(matches!(
            status_to_plugin_error(503, b"", None),
            PluginError::Unavailable(_)
        ));
    }
}
