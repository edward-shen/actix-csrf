#![deny(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery)]

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
//! Csrf::new().set_enabled(false);
//! ```

use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{self, HeaderValue};
use actix_web::http::{Method, StatusCode};
use actix_web::{HttpMessage, HttpResponse, ResponseError};
use extractor::{BasicExtractor, Extractor};
use generator::TokenRng;
use log::error;
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::fmt::Display;
use std::future::{self, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

pub mod extractor;
pub mod generator;

const DEFAULT_CSRF_TOKEN_NAME: &str = "Csrf-Token";

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
        // I don't really want to leak the error to the client. But I need
        // to log it as CSRF attacks are a thing.
        error!("{}", self);
        HttpResponse::with_body(StatusCode::BAD_REQUEST, "CSRF Error".into())
    }
}

/// Middleware builder. The default will check CSRF on every request but
/// GET and POST. You can specify whether to disable.
pub struct Csrf<Rng, Extractor> {
    inner: Inner<Rng, Extractor>,
}

impl Csrf<StdRng, BasicExtractor> {
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
    /// must explicitly relax these restrictions. This is so users explicitly
    /// weaken the security stance.
    #[must_use]
    pub fn new() -> Self {
        Self::default().cookie_name(format!("__HOST-{}", DEFAULT_CSRF_TOKEN_NAME))
    }
}

impl Default for Csrf<StdRng, BasicExtractor> {
    fn default() -> Self {
        Self {
            inner: Inner::default(),
        }
    }
}

impl<Rng, Extractor> Csrf<Rng, Extractor> {
    /// Control whether we check for the token on requests.
    pub const fn set_enabled(mut self, enabled: bool) -> Self {
        self.inner.csrf_enabled = enabled;
        self
    }

    /// Add an extractor for the specified method.
    pub fn add_extractor(mut self, method: Method, extractor: Extractor) -> Self {
        self.inner.req_extractors.insert(method, extractor);
        self
    }

    /// Replace all the extractors
    pub fn set_extractors(mut self, extractors: HashMap<Method, Extractor>) -> Self {
        self.inner.req_extractors = extractors;
        self
    }

    /// Add a whitelisted endpoint
    pub fn add_whilelist(mut self, method: Method, uri: String) -> Self {
        self.inner.whitelist.insert((method, uri));
        self
    }

    /// Sets the cookie name. Consider prefixing the cookie name with `__Host-`
    /// or `__Secure-` as an additional defense-in-depth measure against CSRF
    /// attacks.
    pub fn cookie_name(mut self, name: String) -> Self {
        self.inner.cookie_name = Rc::new(name);
        self
    }

    /// Sets the `SameSite` attribute on the cookie.
    pub fn same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.inner.same_site = same_site;
        self
    }

    /// Sets the `HttpOnly` attribute on the cookie.
    pub fn http_only(mut self, enabled: bool) -> Self {
        self.inner.http_only = enabled;
        self
    }

    /// Sets the `Secure` attribute on the cookie.
    pub fn secure(mut self, enabled: bool) -> Self {
        self.inner.secure = enabled;
        self
    }
}

impl<S, Rng, Extractor> Transform<S> for Csrf<Rng, Extractor>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse>,
    Rng: TokenRng + Clone,
    Extractor: crate::Extractor + Clone,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse;
    type Error = S::Error;
    type InitError = ();
    type Transform = CsrfMiddleware<S, Rng, Extractor>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(CsrfMiddleware {
            service,
            inner: self.inner.clone(),
        }))
    }
}

pub struct CsrfMiddleware<S, Rng, Extractor> {
    service: S,
    inner: Inner<Rng, Extractor>,
}

#[derive(Clone)]
struct Inner<Rng, Extractor> {
    /// To generate the token
    rng: Rng,
    cookie_name: Rc<String>,
    http_only: bool,
    same_site: Option<SameSite>,
    secure: bool,

    /// If false, will not check at all for CSRF tokens
    csrf_enabled: bool,
    /// Extract the token from an incoming HTTP request. One extractor
    /// per Method.
    req_extractors: HashMap<Method, Extractor>,
    /// Endpoints that are not protected by the middleware.
    /// Mapping of Method to URI.
    whitelist: HashSet<(Method, String)>,
}

impl Default for Inner<StdRng, BasicExtractor> {
    fn default() -> Self {
        // sane defaults?
        let mut req_extractors = HashMap::with_capacity(3);
        req_extractors.insert(
            Method::POST,
            BasicExtractor::Header {
                name: DEFAULT_CSRF_TOKEN_NAME.to_owned(),
            },
        );

        req_extractors.insert(
            Method::PUT,
            BasicExtractor::Header {
                name: DEFAULT_CSRF_TOKEN_NAME.to_owned(),
            },
        );

        req_extractors.insert(
            Method::DELETE,
            BasicExtractor::Header {
                name: DEFAULT_CSRF_TOKEN_NAME.to_owned(),
            },
        );

        Self {
            rng: StdRng::from_entropy(),
            cookie_name: Rc::new(DEFAULT_CSRF_TOKEN_NAME.to_owned()),
            req_extractors,
            csrf_enabled: true,
            http_only: true,
            same_site: Some(SameSite::Strict),
            secure: true,
            whitelist: HashSet::new(),
        }
    }
}

impl<Rng, Extractor> Inner<Rng, Extractor> {
    /// Will return true if the middleware needs to check the CSRF tokens.
    fn should_protect(&self, req: &ServiceRequest) -> bool {
        if self
            .whitelist
            .iter()
            .any(|(method, path)| req.method() == method && req.path() == path)
        {
            return false;
        }

        self.req_extractors.contains_key(req.method()) && self.csrf_enabled
    }

    /// Will extract the token from a cookie that was set previously.
    fn extract_cookie_token(&self, req: &ServiceRequest) -> Result<String, CsrfError> {
        dbg!(req.cookies());
        req.cookie(&self.cookie_name)
            .map(|cookie| cookie.value().to_string())
            .ok_or(CsrfError::MissingCookie)
    }
}

impl<Rng, Extractor: extractor::Extractor> Inner<Rng, Extractor> {
    /// Will extract the matching token from the request.
    fn extract_request_token(&self, req: &ServiceRequest) -> Result<String, CsrfError> {
        // Unwrap. At this point, if we arrive here, there is no doubt we have
        // an extractor or it means there is a coding error.
        self.req_extractors
            .get(req.method())
            .unwrap()
            .extract_token(req)
    }
}

impl<S, Rng, Extractor> Service for CsrfMiddleware<S, Rng, Extractor>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse>,
    Rng: TokenRng,
    Extractor: extractor::Extractor,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse;
    type Error = S::Error;
    type Future = CsrfMiddlewareFuture<S>;

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        // Before request, we need to check that for protected resources, the CSRF
        // tokens are actually there and matching. By default protected resources
        // are everything but GET and OPTIONS but you might want to also protect
        // GET if it has server side effects.
        if self.inner.should_protect(&req) {
            // First make sure the tokens are both here
            let cookie_token = self.inner.extract_cookie_token(&req);
            let req_token = self.inner.extract_request_token(&req);

            match (cookie_token, req_token) {
                (Err(e), _) | (_, Err(e)) => {
                    return CsrfMiddlewareFuture::CsrfError(req.error_response(e));
                }
                (Ok(ref cookie_token), Ok(ref req_token)) if cookie_token != req_token => {
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
                self.inner.rng.generate_token().unwrap(),
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

    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }
}

pub enum CsrfMiddlewareFuture<S: Service<Request = ServiceRequest>> {
    CsrfError(ServiceResponse),
    Passthrough(Passthrough<S::Future>),
}

impl<S> Future for CsrfMiddlewareFuture<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse>,
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
            .map(|(_, value)| String::from(value.to_str().unwrap()))
            .collect();
        assert_eq!(1, cookie_header.len());
        String::from(cookie_header.get(0).unwrap().as_str())
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
            .contains(&format!("__HOST-{}", DEFAULT_CSRF_TOKEN_NAME)));
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
                .wrap(Csrf::new().set_enabled(false))
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
            App::new()
                .wrap(Csrf::new().secure(false).same_site(None))
                .service(
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
            .header("Cookie", cookie)
            .header(DEFAULT_CSRF_TOKEN_NAME, token)
            .to_request();

        dbg!(&req);
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_whitelist() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new().add_whilelist(Method::POST, "/".to_string()))
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
            .contains(&format!("__HOST-{}", DEFAULT_CSRF_TOKEN_NAME)));
    }
}
