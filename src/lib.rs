#![deny(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery, missing_docs)]

//! This crate provides a CSRF middleware to help protect endpoints.
//!
//! The primary entry point is through [`Csrf`], which provides a stateless
//! CSRF mitigation implementation through a double-submit cookie pattern.
//!
//! ## The Double-Submit Cookie Pattern
//!
//! [`Csrf`] uses the double-submit cookie pattern as the mechanism for CSRF
//! mitigation. Generally speaking, the double-submit process is as follows:
//! - User submits a request for a resource that will directly send a CSRF token
//! (such as a login form). The server will respond with a `Set-Cookie` header
//! containing the CSRF token.
//! - The user then submits a request for a protected header. The request must
//! contain a CSRF token that is separate from the cookie.
//! - The server then validates if the CSRF value in the request is the same as
//! the CSRF value in the cookie. If it is, the request is allowed to proceed.
//!
//! This is why this process is known as a double-submit: You submit the CSRF
//! value to a CSRF protected endpoint in two different ways. For more
//! information why this works, see the [Owasp Cheat Sheet][double submit] on
//! Double-Submit Cookies.
//!
//! Note that the double submit pattern has its own weaknesses. While it is
//! a stateless pattern, it is only effective if all subdomains are fully
//! secured and only accept HTTPS connections. Additionally, XSS attacks will
//! render all CSRF mitigation techniques ineffective!
//!
//! ## Usage
//!
//! Using this middleware is simple. You need to configure which endpoints
//! should set a CSRF cookie, and which endpoints need a CSRF cookie.
//!
//! ```
//! # use actix_web::App;
//! # use actix_web::http::Method;
//! use actix_csrf::Csrf;
//! use rand::rngs::StdRng;
//!
//! let csrf = Csrf::<StdRng>::new()
//!                .set_cookie(Method::GET, "/login")
//!                .validate_cookie(Method::POST, "/login");
//! let app = App::new().wrap(csrf);
//! ```
//!
//! Endpoints that set a CSRF cookie can either access the CSRF token through
//! the [`CrsfToken`](extractor::CsrfToken) extractor, or through JavaScript
//! that accesses the cookie if `HttpOnly` is disabled. For example, to access
//! the CSRF token in the responder:
//!
//! ```
//! # use actix_web::{HttpResponse, Responder, get};
//! use actix_csrf::extractor::CsrfToken;
//!
//! #[get("/login")]
//! async fn login_ui(token: CsrfToken) -> impl Responder {
//!     // `token` will contain the csrf value that will be sent as a cookie.
//!     // Render something with the token, e.g. as a hidden input in a form.
//!     println!("csrf value that will be set is: {}", token.get());
//!     HttpResponse::Ok().finish()
//! }
//! ```
//!
//! Finally, endpoints that require a CSRF cookie must validate the CSRF token
//! in the request. This can be done by manually accessing the cookie, or using
//! the [`CsrfCookie`](extractor::CsrfCookie) extractor:
//!
//! ```
//! # use actix_web::{HttpResponse, Responder, post};
//! # use actix_web::web::Form;
//! #
//! # #[derive(serde::Deserialize)]
//! # struct LoginForm { csrf_token: String }
//! use actix_csrf::extractor::CsrfCookie;
//!
//! #[post("/login")]
//! async fn login(cookie: CsrfCookie, form: Form<LoginForm>) -> impl Responder {
//!     if !cookie.validate(&form.csrf_token) {
//!         return HttpResponse::BadRequest().finish();
//!     }
//!
//!     // The CSRF token is valid, so the request can proceed.
//!
//!     // ...Do other stuff here...
//!
//!     HttpResponse::Ok().finish()
//! }
//! ```
//!
//! For simple but complete examples, see the [examples] directory.
//!
//! ## Defense-in-depth Measures
//!
//! By default, this middleware multiple various defense-in-depth measures, such
//! as using a `__Host-` prefix, requiring the cookie to be `secure`,
//! `HttpOnly`, and `SameSite=Strict`. However, it is always recommended to
//! implement more; suggestions are deferred to the [Owasp Cheat Sheet].
//!
//! [double submit]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie
//! [Owasp Cheat sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
//! [examples]: https://github.com/edward-shen/actix-csrf/tree/master/examples

use std::cell::RefCell;
use std::collections::HashSet;
use std::default::Default;
use std::error::Error;
use std::fmt::Display;
use std::future::{self, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::extractor::CsrfToken;

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{self, HeaderValue};
use actix_web::http::Method;
use actix_web::{HttpMessage, HttpResponse, ResponseError};
use cookie::{Cookie, SameSite};
use extractor::CsrfCookie;
use generator::TokenRng;
use rand::SeedableRng;
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
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum CsrfError {
    /// The CSRF Token and the token provided in the headers do not match.
    TokenMismatch,
    /// No CSRF Token in the cookies.
    MissingCookie,
    /// No CSRF Token in the request.
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

/// CSRF middleware to manage CSRF cookies and tokens.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Csrf<Rng> {
    inner: Inner<Rng>,
}

impl<Rng: TokenRng + SeedableRng> Csrf<Rng> {
    /// Creates a CSRF middleware with secure defaults. Namely:
    ///
    /// - The CSRF cookie will be prefixed with `__HOST-`
    /// - `SameSite` is set to `Strict`.
    /// - `Secure` is set.
    /// - `HttpOnly` is set.
    /// - `Path` is set to `/`.
    ///
    /// This represents the strictest possible configuration. Requests must be
    /// always sent over HTTPS. Users must explicitly relax these restrictions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<Rng: TokenRng> Csrf<Rng> {
    /// Creates a CSRF middleware with secure defaults and the provided Rng.
    /// Namely:
    ///
    /// - The CSRF cookie will be prefixed with `__HOST-`
    /// - `SameSite` is set to `Strict`.
    /// - `Secure` is set.
    /// - `HttpOnly` is set.
    /// - `Path` is set to `/`.
    ///
    /// This represents the strictest possible configuration. Requests must be
    /// always sent over HTTPS. Users must explicitly relax these restrictions.
    #[must_use]
    pub fn with_rng(rng: Rng) -> Self {
        Self {
            inner: Inner::with_rng(rng),
        }
    }
}

impl<Rng: TokenRng + SeedableRng> Default for Csrf<Rng> {
    fn default() -> Self {
        Self {
            inner: Inner::default(),
        }
        .cookie_name(DEFAULT_CSRF_COOKIE_NAME.to_string())
    }
}

impl<Rng> Csrf<Rng> {
    /// Control whether we check for the token on requests.
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.inner.csrf_enabled = enabled;
        self
    }

    /// Set a method and path to require to have a CSRF cookie set.
    pub fn validate_cookie(mut self, method: Method, uri: impl ToString) -> Self {
        self.inner.included.insert((method, uri.to_string()));
        self
    }

    /// Set a method and path to set a CSRF cookie. This should be all locations
    /// that whose response should set a cookie (via a `Set-Cookie` header) or
    /// those that need the CSRF token value in the response, such as for forms.
    pub fn set_cookie(mut self, method: Method, uri: impl ToString) -> Self {
        self.inner.set_cookie.insert((method, uri.to_string()));
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

#[derive(Clone, Eq, PartialEq, Debug)]
struct Inner<Rng> {
    /// To generate the token
    rng: RefCell<Rng>,
    cookie_name: Rc<String>,
    http_only: bool,
    same_site: Option<SameSite>,
    secure: bool,

    /// If false, will not check at all for CSRF tokens
    csrf_enabled: bool,
    /// Endpoints that have CSRF protection.
    included: HashSet<(Method, String)>,
    set_cookie: HashSet<(Method, String)>,
}

impl<Rng: TokenRng + SeedableRng> Default for Inner<Rng> {
    fn default() -> Self {
        Self::with_rng(Rng::from_entropy())
    }
}

impl<Rng: TokenRng> Inner<Rng> {
    fn with_rng(rng: Rng) -> Self {
        Self {
            rng: RefCell::new(rng),
            cookie_name: Rc::new(DEFAULT_CSRF_COOKIE_NAME.to_owned()),
            csrf_enabled: true,
            http_only: true,
            same_site: Some(SameSite::Strict),
            secure: true,
            included: HashSet::new(),
            set_cookie: HashSet::new(),
        }
    }
}

impl<Rng> Inner<Rng> {
    /// Will return true if the middleware needs to check the CSRF tokens.
    fn should_protect(&self, req: &ServiceRequest) -> bool {
        let method = req.method().clone();
        let path = req.path().to_string();

        self.csrf_enabled && self.included.contains(&(method, path))
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
        if self.inner.should_protect(&req) {
            // First make sure the tokens are both here
            if let Err(e) = CsrfCookie::from_service_request(&self.inner.cookie_name, &req) {
                return CsrfMiddlewareFuture::CsrfError(req.error_response(e));
            }
        }

        let token = self.inner.rng.borrow_mut().generate_token().unwrap();
        let cookie = {
            let mut cookie_builder = Cookie::build(self.inner.cookie_name.as_ref(), token.clone())
                .http_only(self.inner.http_only)
                .secure(self.inner.secure)
                .path("/");

            if let Some(same_site) = self.inner.same_site {
                cookie_builder = cookie_builder.same_site(same_site);
            }

            cookie_builder.finish()
        };

        let cookie = if self.inner.csrf_enabled
            && self
                .inner
                .set_cookie
                .contains(&(req.method().clone(), req.path().to_string()))
        {
            req.extensions_mut().insert(CsrfToken(token));
            Some(
                HeaderValue::from_str(&cookie.to_string())
                    .expect("cookie to be a valid header value"),
            )
        } else {
            None
        };

        CsrfMiddlewareFuture::Passthrough(Passthrough {
            cookie,
            service: Box::pin(self.service.call(req)),
        })
    }

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }
}

#[doc(hidden)]
#[derive(Debug)]
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
                    if let Some(ref cookie) = inner.cookie {
                        res.response_mut()
                            .headers_mut()
                            // TODO: Find a way to not have to clone.
                            .insert(header::SET_COOKIE, cookie.clone());
                    }

                    Poll::Ready(Ok(res))
                }
                other => other,
            },
        }
    }
}

#[doc(hidden)]
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Passthrough<Fut> {
    cookie: Option<HeaderValue>,
    service: Pin<Box<Fut>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::{web, App, HttpResponse};
    use rand::rngs::StdRng;

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
                .wrap(Csrf::<StdRng>::new().set_cookie(Method::GET, "/"))
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
                .wrap(Csrf::<StdRng>::new().validate_cookie(Method::POST, "/"))
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
                .wrap(
                    Csrf::<StdRng>::new()
                        .validate_cookie(Method::POST, "/")
                        .enabled(false),
                )
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
                .wrap(
                    Csrf::<StdRng>::new()
                        .set_cookie(Method::GET, "/")
                        .validate_cookie(Method::POST, "/"),
                )
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
            .insert_header(("Cookie", cookie))
            .insert_header((DEFAULT_CSRF_TOKEN_NAME, token))
            .to_request();

        dbg!(&req);
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // #[tokio::test]
    // async fn test_whitelist() {
    //     let mut srv = test::init_service(
    //         App::new()
    //             .wrap(Csrf::new().set(Method::POST, "/"))
    //             .service(web::resource("/").route(web::post().to(|| HttpResponse::Ok()))),
    //     )
    //     .await;
    //     let resp = test::call_service(&mut srv, TestRequest::post().uri("/").to_request()).await;
    //     assert_eq!(resp.status(), StatusCode::OK);

    //     // Cookie should be in the response.
    //     let cookie_header: Vec<_> = resp
    //         .headers()
    //         .iter()
    //         .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
    //         .map(|(_, value)| String::from(value.to_str().unwrap()))
    //         .collect();
    //     assert_eq!(1, cookie_header.len());
    //     assert!(cookie_header
    //         .get(0)
    //         .unwrap()
    //         .contains(DEFAULT_CSRF_COOKIE_NAME));
    // }
}
