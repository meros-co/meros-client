//! Clients for the Meros services, in Rust, for every Meros app whatever its
//! language: desktop apps use them directly, and Flutter apps reach them
//! from their Rust core through flutter_rust_bridge.
//!
//! - [`LicenseClient`]: the device license API (activate, renew, release,
//!   sign-in claim with TOTP, claim and seats with the app's sign-in, App
//!   Store redeem, manage and browser-claim links, offline activation) and
//!   [`LicenseLink`] deep links.
//! - [`MerosAuth`]: Sign in with Meros (authorization code with PKCE S256,
//!   rotating refresh tokens in the app's [`TokenStore`]), with a
//!   [`loopback`] redirect for desktop.
//! - [`MerosCloud`]: profiles, versioned documents, files, accounts and
//!   entitlements.
//! - [`SupportApi`], [`SupportInbox`] and [`ReplyTracker`]: support tickets
//!   and push-token registration.
//! - [`Emitter`]: the Meros Event Envelope v1, logged locally and delivered
//!   in batches.
//! - [`fake::FakeMeros`] (feature `fake`): the services in memory, for app
//!   tests with no network.
//!
//! Nothing here names a host: the app passes its issuer, base URLs and
//! client id (see [`Environment`]). Every request goes through a
//! [`Transport`]; errors carry the server's code unchanged in
//! [`Error::code`].

pub mod auth;
pub mod cloud;
pub mod device;
pub mod environment;
pub mod error;
pub mod events;
pub mod http;
pub mod license;
pub mod server;
pub mod support;

#[cfg(feature = "loopback")]
pub mod loopback;

#[cfg(feature = "fake")]
pub mod fake;

pub use auth::{
    AccessTokenSource, AuthConfig, MemoryTokenStore, MerosAuth, MerosUser, Pkce, StaticToken,
    TokenStore,
};
pub use cloud::{
    MerosAccount, MerosCloud, MerosDoc, MerosDocInfo, MerosDocVersion, MerosFile, MerosProfile,
    file_hash,
};
#[cfg(feature = "entitlement")]
pub use device::EntitlementDevice;
#[cfg(any(test, feature = "fake"))]
pub use device::testing;
pub use device::{DeviceIdentity, DeviceSigner, LicenseDevice};
pub use environment::Environment;
pub use error::Error;
pub use events::{
    Actor, Collector, Emitter, EmitterConfig, Envelope, Event, FlushReport, Severity, Source,
    Subject,
};
#[cfg(feature = "reqwest")]
pub use http::ReqwestTransport;
pub use http::{BoxFuture, HttpRequest, HttpResponse, Transport};
pub use license::{
    AuthResult, LicenseClient, LicenseConfig, LicenseLink, LicenseSeat, SignInClaim,
};
pub use server::{
    ServerConfig, ServerDevice, ServerLicence, ServerLicenseClient, ServerRenewal, verify_licence,
};
pub use support::{
    AccountSupportApi, MemoryTicketSeenStore, ReplyTracker, SupportApi, SupportInbox,
    SupportMessage, SupportThread, SupportTicket, TicketSeenStore, TicketStatus,
    support_ticket_id_from_uri,
};
