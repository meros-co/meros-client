//! Which service a build talks to. The crate has no built-in host: the app
//! names its production and staging hosts, and the build picks one.

/// Production or staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Production,
    Staging,
}

impl Environment {
    /// Release builds use production; debug, profile and test builds use
    /// staging. `release` is the app's own notion of a release build (for a
    /// Rust app, `!cfg!(debug_assertions)`; for Flutter, `kReleaseMode`), and
    /// `testing` (such as a test-build flag) forces staging even in release.
    pub fn for_build(release: bool, testing: bool) -> Environment {
        if release && !testing {
            Environment::Production
        } else {
            Environment::Staging
        }
    }

    /// The host for this environment.
    pub fn pick<'a>(self, production: &'a str, staging: &'a str) -> &'a str {
        match self {
            Environment::Production => production,
            Environment::Staging => staging,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_release_build_that_is_not_a_test_reaches_production() {
        let pick = |release, testing| {
            Environment::for_build(release, testing)
                .pick("https://prod.test", "https://staging.test")
        };
        assert_eq!(pick(true, false), "https://prod.test");
        assert_eq!(pick(true, true), "https://staging.test");
        assert_eq!(pick(false, false), "https://staging.test");
        assert_eq!(pick(false, true), "https://staging.test");
    }
}
