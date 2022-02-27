//! Contains various extractors related to CSRF tokens.

use std::future::{ready, Future, Ready};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::{CsrfError, DEFAULT_CSRF_COOKIE_NAME, DEFAULT_CSRF_TOKEN_NAME};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Serialize};

/// Extractor to get the CSRF header from the request.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CsrfHeader(CsrfToken);

impl CsrfHeader {
    /// Checks if the header matches the CSRF header.
    pub fn validate(&self, header_value: impl AsRef<str>) -> bool {
        self.0.as_ref() == header_value.as_ref()
    }
}

impl CsrfGuarded for CsrfHeader {
    fn csrf_token(&self) -> &CsrfToken {
        &self.0
    }
}

impl FromRequest for CsrfHeader {
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let header_name: &str = req
            .app_data::<CsrfHeaderConfig>()
            .map_or(DEFAULT_CSRF_TOKEN_NAME, |v| v.header_name.as_ref());

        if let Some(header) = req.headers().get(header_name) {
            return match header.to_str() {
                Ok(header) => ready(Ok(Self(CsrfToken(header.to_string())))),
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

impl CsrfCookie {
    /// Checks if the input matches the cookie.
    pub fn validate(&self, token: impl AsRef<str>) -> bool {
        self.0 == token.as_ref()
    }

    fn from_request_sync(req: &HttpRequest) -> Result<Self, CsrfError> {
        let cookie_name = req
            .app_data::<CsrfCookieConfig>()
            .map_or(DEFAULT_CSRF_COOKIE_NAME, |v| v.cookie_name.as_ref());

        req.cookie(cookie_name)
            .ok_or(CsrfError::MissingCookie)
            .map(|cookie| Self(cookie.value().to_string()))
    }
}

impl FromRequest for CsrfCookie {
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Self::from_request_sync(req))
    }
}

impl AsRef<str> for CsrfCookie {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CsrfToken(pub(crate) String);

impl Serialize for CsrfToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct("Csrf Token", &self.0)
    }
}

impl<'de> Deserialize<'de> for CsrfToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CsrfTokenVisitor;
        impl<'de> Visitor<'de> for CsrfTokenVisitor {
            type Value = CsrfToken;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid csrf token")
            }

            fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(CsrfToken(v))
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(CsrfToken(v.to_string()))
            }

            fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(CsrfToken(v.to_string()))
            }
        }

        deserializer.deserialize_newtype_struct("Csrf Token", CsrfTokenVisitor)
    }
}

impl CsrfToken {
    /// Retrieves a reference of the csrf token.
    #[must_use]
    pub fn get(&self) -> &str {
        &self.0
    }

    /// Consumes the struct, returning the underlying string.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // false positive
    pub fn into_inner(self) -> String {
        self.0
    }

    fn from_request_sync(req: &HttpRequest) -> Result<Self, CsrfError> {
        req.extensions()
            .get::<Self>()
            .cloned()
            .ok_or(CsrfError::MissingToken)
    }
}

impl AsRef<str> for CsrfToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromRequest for CsrfToken {
    type Error = CsrfError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Self::from_request_sync(req))
    }
}

/// This extractor wraps another extractor that returns some inner type that
/// holds a CSRF token, and performs validation on the token. If the token is
/// missing or invalid, then the extractor will return an error.
///
/// ```
/// use actix_csrf::extractor::{Csrf, CsrfGuarded, CsrfToken};
/// use actix_web::{post, Responder};
/// use actix_web::web::Form;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Login {
///    csrf: CsrfToken,
///    email: String,
///    password: String,
/// }
///
/// impl CsrfGuarded for Login {
///     fn csrf_token(&self) -> &CsrfToken {
///         &self.csrf
///     }
/// }
///
/// #[post("/login")]
/// async fn login(form: Csrf<Form<Login>>) -> impl Responder {
///    // If we got here, then the CSRF token passed validation!
///    format!("hello, {}, your password is {}", &form.email, &form.password)
/// }
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Csrf<Inner>(Inner);

impl<Inner> Deref for Csrf<Inner> {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Inner> DerefMut for Csrf<Inner> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Inner> FromRequest for Csrf<Inner>
where
    Inner: FromRequest + CsrfGuarded,
{
    type Error = CsrfExtractorError<Inner::Error>;
    type Future = CsrfExtractorFuture<Inner::Future>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        CsrfExtractorFuture {
            csrf_token: CsrfCookie::from_request_sync(req),
            inner: Box::pin(Inner::from_request(req, payload)),
        }
    }
}

macro_rules! derive_csrf_guarded {
    ($type:path) => {
        impl<T> CsrfGuarded for $type
        where
            T: CsrfGuarded,
        {
            fn csrf_token(&self) -> &CsrfToken {
                self.0.csrf_token()
            }
        }
    };
}

derive_csrf_guarded!(actix_web::web::Form<T>);
derive_csrf_guarded!(actix_web::web::Json<T>);

/// Polls the underlying future, returning the underlying result if and only if
/// the CSRF token is valid.
pub struct CsrfExtractorFuture<Fut> {
    csrf_token: Result<CsrfCookie, CsrfError>,
    inner: Pin<Box<Fut>>,
}

impl<Fut, FutOut, FutErr> Future for CsrfExtractorFuture<Fut>
where
    Fut: Future<Output = Result<FutOut, FutErr>>,
    FutOut: CsrfGuarded,
{
    type Output = Result<Csrf<FutOut>, CsrfExtractorError<FutErr>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner.as_mut().poll(cx) {
            Poll::Ready(Ok(out)) => {
                if let Ok(ref token) = self.csrf_token {
                    if out.csrf_token().as_ref() == token.as_ref() {
                        return Poll::Ready(Ok(Csrf(out)));
                    }
                }

                Poll::Ready(Err(CsrfExtractorError::InvalidToken))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(CsrfExtractorError::Inner(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// This trait represents types who have a field that represents a CSRF token.
///
/// This trait is required on an underlying type for the [`Csrf`] extractor to
/// correctly function.
pub trait CsrfGuarded {
    /// Retrieves the CSRF token from the struct.
    fn csrf_token(&self) -> &CsrfToken;
}

/// Represents an error that occurs when polling [`CsrfExtractorFuture`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CsrfExtractorError<Inner> {
    /// A CSRF token was not found, or was invalid.
    InvalidToken,
    /// An underlying error occurred.
    Inner(Inner),
}

impl<Inner> From<CsrfExtractorError<Inner>> for actix_web::error::Error
where
    Inner: Into<Self>,
{
    fn from(e: CsrfExtractorError<Inner>) -> Self {
        match e {
            CsrfExtractorError::InvalidToken => CsrfError::TokenMismatch.into(),
            CsrfExtractorError::Inner(e) => e.into(),
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
