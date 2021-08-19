//! Contains various extractors related to CSRF tokens.

use std::future::{ready, Ready};

use crate::{CsrfError, DEFAULT_CSRF_COOKIE_NAME, DEFAULT_CSRF_TOKEN_NAME};

use actix_web::dev::{Payload, ServiceRequest};
use actix_web::{FromRequest, HttpRequest};

/// Extractor to get the CSRF header from the request.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CsrfHeader(String);

impl CsrfHeader {
    /// Checks if the header matches the CSRF header.
    pub fn validate(&self, header_value: impl AsRef<str>) -> bool {
        self.0 == header_value.as_ref()
    }
}

impl FromRequest for CsrfHeader {
    type Config = CsrfHeaderConfig;
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let header_name: &str = req
            .app_data::<Self::Config>()
            .map_or(DEFAULT_CSRF_TOKEN_NAME, |v| v.header_name.as_ref());

        if let Some(header) = req.headers().get(header_name) {
            return match header.to_str() {
                Ok(header) => ready(Ok(Self(header.to_string()))),
                Err(_) => ready(Err(CsrfError::MissingToken)),
            };
        }

        ready(Err(CsrfError::MissingCookie))
    }
}

impl AsRef<str> for CsrfHeader {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

/// Configuration struct for [`CsrfHeader`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CsrfHeaderConfig {
    header_name: String,
}

impl Default for CsrfHeaderConfig {
    fn default() -> Self {
        Self {
            header_name: DEFAULT_CSRF_TOKEN_NAME.to_string(),
        }
    }
}

/// Extractor to get the CSRF cookie from the request.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CsrfCookie(String);

impl AsRef<str> for CsrfCookie {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl CsrfCookie {
    pub(crate) fn from_service_request(
        cookie_name: &str,
        req: &ServiceRequest,
    ) -> Result<Self, CsrfError> {
        req.cookie(cookie_name)
            .ok_or(CsrfError::MissingCookie)
            .map(|cookie| Self(cookie.value().to_string()))
    }

    /// Checks if the input matches the cookie.
    pub fn validate(&self, token: impl AsRef<str>) -> bool {
        self.0 == token.as_ref()
    }
}

impl FromRequest for CsrfCookie {
    type Config = CsrfCookieConfig;
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let cookie_name = req
            .app_data::<Self::Config>()
            .map_or(DEFAULT_CSRF_COOKIE_NAME, |v| v.cookie_name.as_ref());

        ready(
            req.cookie(cookie_name)
                .ok_or(CsrfError::MissingCookie)
                .map(|cookie| Self(cookie.value().to_string())),
        )
    }
}

/// Configuration struct for [`CsrfCookie`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CsrfCookieConfig {
    cookie_name: String,
}

impl Default for CsrfCookieConfig {
    fn default() -> Self {
        Self {
            cookie_name: DEFAULT_CSRF_COOKIE_NAME.to_string(),
        }
    }
}

/// Extractor to get the CSRF token that will be set as a cookie.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CsrfToken(pub(crate) String);

impl CsrfToken {
    /// Retrieves a reference of the csrf token.
    #[must_use]
    pub fn get(&self) -> &str {
        &self.0
    }

    /// Consumes the struct, returning the underlying string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for CsrfToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromRequest for CsrfToken {
    type Config = ();
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(
            req.extensions()
                .get::<Self>()
                .cloned()
                .ok_or(CsrfError::MissingToken),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::DEFAULT_CSRF_COOKIE_NAME;

    use super::*;

    use actix_web::http::header;
    use actix_web::test::TestRequest;

    #[tokio::test]
    async fn extract_from_header() -> Result<(), Box<dyn Error>> {
        let req = TestRequest::default()
            .insert_header((DEFAULT_CSRF_TOKEN_NAME, "sometoken"))
            .to_http_request();
        let token = CsrfHeader::extract(&req).await?;
        assert!(token.validate("sometoken"));

        Ok(())
    }

    #[tokio::test]
    async fn not_found_header() {
        let req = TestRequest::default()
            .insert_header(("fake", "sometoken"))
            .to_http_request();
        let token = CsrfHeader::extract(&req).await;
        assert!(token.is_err());
    }

    #[tokio::test]
    async fn extract_from_cookie() -> Result<(), Box<dyn Error>> {
        let req = TestRequest::default()
            .insert_header((
                header::COOKIE,
                format!("{}=sometoken", DEFAULT_CSRF_COOKIE_NAME),
            ))
            .to_http_request();

        let token = CsrfCookie::extract(&req).await?;
        assert!(token.validate("sometoken"));
        Ok(())
    }

    #[tokio::test]
    async fn not_found_cookie() {
        let req = TestRequest::default()
            .insert_header(("fake", "sometoken"))
            .to_http_request();
        let token = CsrfCookie::extract(&req).await;
        assert!(token.is_err());
    }
}
