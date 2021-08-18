#![deny(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery, missing_docs)]

//! CSRF attack mitigation.
//!
//! This middleware is mitigating the CSRF attacks by using the double token submit
//! A token is sent to the client via the set-cookie header. Then, the client will
//! send the token in its request by two different ways:
//! - First, in the cookie header.
//! - Then in its request body/header/parameters depending on the middleware configuration.
//!
//! For methods that are checked (POST, PUT, DELETE...), any issue will return an error
//! 400.
//!
//! Basic usage is:
//! ```
//!
//! use actix_csrf::Csrf;
//! use actix_web::{HttpServer, web, App, HttpResponse};
//!
//! let server = HttpServer::new(|| {
//!     App::new()
//!         .wrap(Csrf::new())
//!         .service(web::resource("/")
//!             // by default will not check get
//!             .route(web::get().to(|| HttpResponse::Ok()))
//!             // by default will check post
//!             .route(web::post().to(|| HttpResponse::Ok())))
//! });
//!
//! ```
//!
//! You can deactivate the protection (for example for dev mode or unit tests.
//! ```
//! use actix_csrf::Csrf;
//! Csrf::new().enabled(false);
//! ```

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{self, HeaderValue};
use actix_web::http::Method;
use actix_web::{HttpResponse, ResponseError};
use cookie::{Cookie, SameSite};
use extractor::{CsrfCookie, CsrfHeader};
use generator::TokenRng;
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::cell::RefCell;
use std::collections::HashSet;
use std::default::Default;
use std::error::Error;
use std::fmt::Display;
use std::future::{self, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use tracing::warn;

pub mod extractor;
pub mod generator;

macro_rules! token_name {
    () => {
        "Csrf-Token"
    };
}

const DEFAULT_CSRF_TOKEN_NAME: &str = token_name!();
const DEFAULT_CSRF_COOKIE_NAME: &str = concat!("__HOST-", token_name!());

/// Internal errors that can happen when processing CSRF tokens.
#[derive(Debug)]
pub enum CsrfError {
    /// The CSRF Token and the token provided in the headers do not match
    TokenMismatch,
    /// No CSRF Token in the cookies.
    MissingCookie,
    /// No CSRF Token in the request (headers/body...).
    MissingToken,
}

impl Display for CsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsrfError::TokenMismatch => write!(f, "The CSRF Tokens do not match"),
            CsrfError::MissingCookie => write!(f, "The CSRF Cookie is missing"),
            CsrfError::MissingToken => write!(f, "The CSRF Header is missing"),
        }
    }
}

impl ResponseError for CsrfError {
    fn error_response(&self) -> HttpResponse {
        warn!("Potential CSRF attack: {}", self);
        HttpResponse::BadRequest().finish()
    }
}

impl Error for CsrfError {}

/// Middleware builder. The default will check CSRF on every request but
/// GET and POST. You can specify whether to disable.
pub struct Csrf<Rng> {
    inner: Inner<Rng>,
}

impl Csrf<StdRng> {
    /// Creates a CSRF middleware with secure defaults. Namely:
    ///
    /// - The CSRF cookie will be prefixed with `__HOST-`
    /// - `SameSite` is set to `Strict`.
    /// - `Secure` is set.
    /// - `HttpOnly` is set.
    /// - `Path` is set to `/`.
    ///
    /// This represents the strictest possible configuration. As a result,
    /// requests must be sent over HTTPS, even in development scenarios. Users
    /// must explicitly relax these restrictions. This is so users must
    /// explicitly weaken the security stance.
    #[must_use]
    pub fn new() -> Self {
        Self::default().cookie_name(DEFAULT_CSRF_COOKIE_NAME.to_string())
    }
}

impl Default for Csrf<StdRng> {
    fn default() -> Self {
        Self {
            inner: Inner::default(),
        }
    }
}

impl<Rng> Csrf<Rng> {
    /// Control whether we check for the token on requests.
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.inner.csrf_enabled = enabled;
        self
    }

    /// Exclude a method and path from CSRF protection.
    pub fn exclude(mut self, method: Method, uri: impl ToString) -> Self {
        self.inner.excluded.insert((method, uri.to_string()));
        self
    }

    /// Sets the cookie name. Consider prefixing the cookie name with `__Host-`
    /// or `__Secure-` as an additional defense-in-depth measure against CSRF
    /// attacks.
    pub fn cookie_name(mut self, name: impl ToString) -> Self {
        self.inner.cookie_name = Rc::new(name.to_string());
        self
    }

    /// Sets the `SameSite` attribute on the cookie.
    pub const fn same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.inner.same_site = same_site;
        self
    }

    /// Sets the `HttpOnly` attribute on the cookie.
    pub const fn http_only(mut self, enabled: bool) -> Self {
        self.inner.http_only = enabled;
        self
    }

    /// Sets the `Secure` attribute on the cookie.
    pub const fn secure(mut self, enabled: bool) -> Self {
        self.inner.secure = enabled;
        self
    }
}

impl<S, Rng> Transform<S, ServiceRequest> for Csrf<Rng>
where
    S: Service<ServiceRequest, Response = ServiceResponse>,
    Rng: TokenRng + Clone,
{
    type Response = ServiceResponse;
    type Error = S::Error;
    type InitError = ();
    type Transform = CsrfMiddleware<S, Rng>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(CsrfMiddleware {
            service,
            inner: self.inner.clone(),
        }))
    }
}

#[doc(hidden)]
pub struct CsrfMiddleware<S, Rng> {
    service: S,
    inner: Inner<Rng>,
}

#[derive(Clone)]
struct Inner<Rng> {
    /// To generate the token
    rng: RefCell<Rng>,
    cookie_name: Rc<String>,
    http_only: bool,
    same_site: Option<SameSite>,
    secure: bool,

    /// If false, will not check at all for CSRF tokens
    csrf_enabled: bool,
    /// Endpoints that are not protected by the middleware.
    /// Mapping of Method to URI.
    excluded: HashSet<(Method, String)>,
}

impl Default for Inner<StdRng> {
    fn default() -> Self {
        Self {
            rng: RefCell::new(StdRng::from_entropy()),
            cookie_name: Rc::new(DEFAULT_CSRF_COOKIE_NAME.to_owned()),
            csrf_enabled: true,
            http_only: true,
            same_site: Some(SameSite::Strict),
            secure: true,
            excluded: HashSet::new(),
        }
    }
}

impl<Rng> Inner<Rng> {
    /// Will return true if the middleware needs to check the CSRF tokens.
    fn should_protect(&self, req: &ServiceRequest) -> bool {
        if self
            .excluded
            .iter()
            .any(|(method, path)| req.method() == method && req.path() == path)
        {
            return false;
        }

        matches!(*req.method(), Method::POST | Method::PATCH | Method::DELETE) && self.csrf_enabled
    }
}

impl<S, Rng> Service<ServiceRequest> for CsrfMiddleware<S, Rng>
where
    S: Service<ServiceRequest, Response = ServiceResponse>,
    Rng: TokenRng,
{
    type Response = ServiceResponse;
    type Error = S::Error;
    type Future = CsrfMiddlewareFuture<S>;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Before request, we need to check that for protected resources, the CSRF
        // tokens are actually there and matching. By default protected resources
        // are everything but GET and OPTIONS but you might want to also protect
        // GET if it has server side effects.
        if self.inner.should_protect(&req) {
            // First make sure the tokens are both here
            let cookie_token = CsrfCookie::from_service_request(&self.inner.cookie_name, &req);
            let req_token = CsrfHeader::from_service_request(DEFAULT_CSRF_TOKEN_NAME, &req);

            match (cookie_token, req_token) {
                (Err(e), _) | (_, Err(e)) => {
                    return CsrfMiddlewareFuture::CsrfError(req.error_response(e));
                }
                (Ok(cookie_token), Ok(req_token))
                    if cookie_token.as_ref() != req_token.as_ref() =>
                {
                    return CsrfMiddlewareFuture::CsrfError(
                        req.error_response(CsrfError::TokenMismatch),
                    );
                }
                _ => (), // csrf tokens match, continue
            }
        }

        let cookie = {
            let mut cookie_builder = Cookie::build(
                self.inner.cookie_name.as_ref(),
                self.inner.rng.borrow_mut().generate_token().unwrap(),
            )
            .http_only(self.inner.http_only)
            .secure(self.inner.secure)
            .path("/");

            if let Some(same_site) = self.inner.same_site {
                cookie_builder = cookie_builder.same_site(same_site);
            }

            cookie_builder.finish()
        };

        CsrfMiddlewareFuture::Passthrough(Passthrough {
            cookie: HeaderValue::from_str(&cookie.to_string())
                .expect("cookie to be a valid header value"),
            enabled: self.inner.csrf_enabled,
            service: Box::pin(self.service.call(req)),
        })
    }

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }
}

#[doc(hidden)]
pub enum CsrfMiddlewareFuture<S: Service<ServiceRequest>> {
    /// A CSRF issue was detected.
    CsrfError(ServiceResponse),
    /// No CSRF issue was detected, so we pass the request through.
    Passthrough(Passthrough<S::Future>),
}

impl<S> Future for CsrfMiddlewareFuture<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse>,
{
    type Output = Result<ServiceResponse, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            CsrfMiddlewareFuture::CsrfError(error) => {
                // TODO: Find a way to not have to clone.
                let req = error.request().clone();
                let mut new_error = ServiceResponse::new(req, HttpResponse::NoContent().finish());
                std::mem::swap(&mut new_error, error);
                Poll::Ready(Ok(new_error))
            }
            CsrfMiddlewareFuture::Passthrough(inner) => match inner.service.as_mut().poll(cx) {
                Poll::Ready(Ok(mut res)) => {
                    if inner.enabled {
                        res.response_mut()
                            .headers_mut()
                            // TODO: Find a way to not have to clone.
                            .insert(header::SET_COOKIE, inner.cookie.clone());
                    }

                    Poll::Ready(Ok(res))
                }
                other => other,
            },
        }
    }
}

#[doc(hidden)]
pub struct Passthrough<Fut> {
    cookie: HeaderValue,
    enabled: bool,
    service: Pin<Box<Fut>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::{web, App, HttpResponse};

    fn get_token_from_resp(resp: &ServiceResponse) -> String {
        let cookie = get_cookie_from_resp(resp);
        // should be something like "Csrf-Token=NHMWzEq7nAFZR56jnanhFv6WJdeEAyhy; Path=/"
        let token_header = cookie.split('=');
        let token = token_header.skip(1).take(1).collect::<Vec<_>>()[0];
        let token = token.split(';').next().unwrap();
        String::from(token)
    }

    fn get_cookie_from_resp(resp: &ServiceResponse) -> String {
        let cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| value.to_str().unwrap())
            .map(|v| v.split(';').next().unwrap())
            .collect();
        assert_eq!(1, cookie_header.len());
        String::from(*cookie_header.get(0).unwrap())
    }

    // Check that the CSRF token is correctly attached to the response
    #[tokio::test]
    async fn test_attach_token() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new())
                .service(web::resource("/").to(|| HttpResponse::Ok())),
        )
        .await;
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Cookie should be in the response.
        let cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| String::from(value.to_str().unwrap()))
            .collect();
        assert_eq!(1, cookie_header.len());
        assert!(cookie_header
            .get(0)
            .unwrap()
            .contains(DEFAULT_CSRF_COOKIE_NAME));
    }

    // With default protection, POST requests is rejected.
    #[tokio::test]
    async fn test_post_request_rejected() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new())
                .service(web::resource("/").route(web::post().to(|| HttpResponse::Ok()))),
        )
        .await;
        let resp = test::call_service(&mut srv, TestRequest::post().uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Can disable protection for unit tests.
    #[tokio::test]
    async fn test_post_accepted_with_disabled() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new().enabled(false))
                .service(web::resource("/").route(web::post().to(|| HttpResponse::Ok()))),
        )
        .await;
        let resp = test::call_service(&mut srv, TestRequest::post().uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| String::from(value.to_str().unwrap()))
            .collect();

        assert_eq!(0, cookie_header.len());
    }

    /// Will use double submit method.
    #[tokio::test]
    async fn double_submit_correct_token() {
        let mut srv = test::init_service(
            App::new().wrap(Csrf::new()).service(
                web::resource("/")
                    .route(web::get().to(|| HttpResponse::Ok()))
                    .route(web::post().to(|| HttpResponse::Ok())),
            ),
        )
        .await;

        // First, let's get the token as a client.
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/").to_request()).await;

        dbg!(&resp);

        let token = get_token_from_resp(&resp);
        let cookie = get_cookie_from_resp(&resp);

        // Now we can do another request to a protected endpoint.
        let req = TestRequest::post()
            .uri("/")
            .insert_header(("Cookie", cookie))
            .insert_header((DEFAULT_CSRF_TOKEN_NAME, token))
            .to_request();

        dbg!(&req);
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_whitelist() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new().exclude(Method::POST, "/"))
                .service(web::resource("/").route(web::post().to(|| HttpResponse::Ok()))),
        )
        .await;
        let resp = test::call_service(&mut srv, TestRequest::post().uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Cookie should be in the response.
        let cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| String::from(value.to_str().unwrap()))
            .collect();
        assert_eq!(1, cookie_header.len());
        assert!(cookie_header
            .get(0)
            .unwrap()
            .contains(DEFAULT_CSRF_COOKIE_NAME));
    }
}
