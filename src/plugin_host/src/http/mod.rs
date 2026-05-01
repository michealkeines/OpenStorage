//! Shared HTTP layer for plugins.
//!
//! Every plugin built on HTTP routes its requests through this module rather
//! than through `reqwest` directly. The point isn't convenience — it's that
//! **rate-limit detection is a property of this layer, not of the plugin**.
//! Plugins can't forget to parse `Retry-After`, can't disagree on what HTTP
//! 429 means, and can't accidentally surface a generic `Unavailable` when
//! the server told them exactly how long to back off.
//!
//! Architecture:
//!
//! - `HttpClient` wraps `reqwest::Client`. Its `execute` method always runs
//!   incoming responses through a `StatusInterpreter` which maps HTTP codes
//!   to typed `PluginError`s. 429 / 503 with `Retry-After` always become
//!   `PluginError::RateLimited`.
//! - `RateLimitDetector` is the extension point: backends like Telegram and
//!   Discord encode the `retry_after` in the JSON body, not in headers.
//!   Each plugin can install a custom detector that inspects the body
//!   before the default Retry-After header parser runs.
//! - The default detector handles the header-only case correctly. Pure
//!   HTTP plugins (the testbench, uguu.se) need no extra code.
//!
//! Net effect: when the dispatcher asks "is this provider rate-limited?",
//! the answer comes from the wire, not from how diligent the plugin author
//! was about parsing.

pub mod client;
pub mod ratelimit;
pub mod error;

pub use client::{Body, HttpClient, HttpClientConfig, HttpRequest, HttpResponse};
pub use error::status_to_plugin_error;
pub use ratelimit::{
    DefaultDetector, DiscordDetector, RateLimitDetector, RateLimitInfo, TelegramDetector,
};
