//! Extractor are used to extract the CSRF token.
//!
//! The token can be stored in different ways (POST body, headers,
//! GET params, session...).
//!
//! Basic extractors are provided:
//! - from header
//! - from cookie
//! - from url parameters
//!
//! You can use the trait `Extractor` to add a custom extractor.

use std::future::{ready, Ready};

use crate::{CsrfError, DEFAULT_CSRF_COOKIE_NAME, DEFAULT_CSRF_TOKEN_NAME};
use actix_web::dev::{Payload, ServiceRequest};
use actix_web::{FromRequest, HttpRequest};

pub struct CsrfHeader(String);

impl CsrfHeader {
    pub(crate) fn from_service_request(
        header_name: &str,
        req: &ServiceRequest,
    ) -> Result<Self, CsrfError> {
        req.headers()
            .get(header_name)
            .ok_or(CsrfError::MissingToken)
            .and_then(|header| header.to_str().map_err(|_| CsrfError::MissingToken))
            .map(String::from)
            .map(Self)
    }

    pub fn get(&self) -> &str {
        &self.0
    }

    /// Consumes the struct, returning the underlying string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for CsrfHeader {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromRequest for CsrfHeader {
    type Config = CsrfHeaderConfig;
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let header_name: &str = req
            .app_data::<Self::Config>()
            .map(|v| v.header_name.as_ref())
            .unwrap_or(DEFAULT_CSRF_TOKEN_NAME);

        if let Some(header) = req.headers().get(dbg!(header_name)) {
            if let Ok(cookie) = header.to_str() {
                return ready(Ok(Self(cookie.to_string())));
            }
        }

        ready(Err(CsrfError::MissingCookie))
    }
}

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

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CsrfCookie(String);

impl CsrfCookie {
    pub(crate) fn from_service_request(
        cookie_name: &str,
        req: &ServiceRequest,
    ) -> Result<Self, CsrfError> {
        req.cookie(cookie_name)
            .ok_or(CsrfError::MissingCookie)
            .map(|cookie| Self(cookie.value().to_string()))
    }

    pub fn get(&self) -> &str {
        &self.0
    }

    /// Consumes the struct, returning the underlying string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for CsrfCookie {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromRequest for CsrfCookie {
    type Config = CsrfCookieConfig;
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let cookie_name = req
            .app_data::<Self::Config>()
            .map(|v| v.cookie_name.as_ref())
            .unwrap_or(DEFAULT_CSRF_COOKIE_NAME);

        ready(
            req.cookie(cookie_name)
                .ok_or(CsrfError::MissingCookie)
                .map(|cookie| Self(cookie.value().to_string())),
        )
    }
}

pub struct CsrfCookieConfig {
    cookie_name: String,
}

impl Default for CsrfCookieConfig {
    fn default() -> Self {
        Self {
            cookie_name: Default::default(),
        }
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
        assert_eq!(token.get(), "sometoken");

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
        assert_eq!(token.get(), "sometoken");
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
