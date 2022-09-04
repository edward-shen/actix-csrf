#![deny(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery, clippy::cargo, missing_docs)]

//! This crate provides a CSRF middleware to help protect endpoints.
//!
//! The primary entry point is through [`CsrfMiddleware`] and the
//! [`Csrf`](extractor::Csrf) extractor, which together provides a stateless
//! CSRF mitigation implementation through a double-submit cookie pattern.
//!
//! ## The Double-Submit Cookie Pattern
//!
//! [`CsrfMiddleware`] uses the double-submit cookie pattern as the mechanism
//! for CSRF mitigation. Generally speaking, the double-submit process is as
//! follows:
//!
//! - User submits a request for a resource that will directly send a CSRF token
//! (such as a login form). The server will respond with a `Set-Cookie` header
//! containing the CSRF token.
//! - The user then submits a request that contains the CSRF token, either
//! through a custom header or in the request itself. The request must contain a
//! CSRF token that is separate from the cookie.
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
//! Using this middleware is simple. You just need to configure which endpoints
//! should set a CSRF cookie, and then use [`Csrf`](extractor::Csrf) trait to
//! transparently validate the cookie.
//!
//! ```
//! # use actix_web::App;
//! # use actix_web::http::Method;
//! use actix_csrf::CsrfMiddleware;
//! use rand::rngs::StdRng;
//!
//! let csrf = CsrfMiddleware::<StdRng>::new().set_cookie(Method::GET, "/login");
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
//!     println!("csrf value that will be set is: {:?}", token.get());
//!     HttpResponse::Ok().finish()
//! }
//! ```
//!
//! Then, endpoints that require a CSRF cookie must validate the CSRF token
//! in the request. This can be done by manually accessing the cookie, or by
//! using the [`Csrf`](extractor::Csrf) extractor, which will validate the CSRF
//! token for you if [`CsrfGuarded`](extractor::CsrfGuarded) is implemented in
//! the underlying struct.
//!
//! ```
//! # use actix_web::{HttpResponse, Responder, post};
//! # use actix_web::web::Form;
//! use actix_csrf::extractor::{Csrf, CsrfGuarded, CsrfToken};
//!
//! #[derive(serde::Deserialize)]
//! struct LoginForm { csrf_token: CsrfToken }
//!
//! impl CsrfGuarded for LoginForm {
//!     fn csrf_token(&self) -> &CsrfToken {
//!         &self.csrf_token
//!     }
//! }
//!
//! #[post("/login")]
//! async fn login(form: Csrf<Form<LoginForm>>) -> impl Responder {
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
use actix_web::error::InternalError;
use actix_web::http::header::{self, HeaderValue};
use actix_web::http::{Method, StatusCode};
use actix_web::{HttpMessage, HttpResponse, ResponseError};
use cookie::{Cookie, SameSite};
use extractor::CsrfCookieConfig;
use rand::SeedableRng;
use tracing::{error, warn};

pub mod extractor;
mod generator;

pub use crate::generator::TokenRng;

macro_rules! token_name {
    () => {
        "Csrf-Token"
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! host_prefix {
    () => {
        "__Host-"
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! secure_prefix {
    () => {
        "__Secure-"
    };
}

const DEFAULT_CSRF_TOKEN_NAME: &str = token_name!();
const DEFAULT_CSRF_COOKIE_NAME: &str = concat!(host_prefix!(), token_name!());

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
            Self::TokenMismatch => write!(f, "The CSRF Tokens do not match"),
            Self::MissingCookie => write!(f, "The CSRF Cookie is missing"),
            Self::MissingToken => write!(f, "The CSRF Header is missing"),
        }
    }
}

impl ResponseError for CsrfError {
    fn error_response(&self) -> HttpResponse {
        warn!("Potential CSRF attack: {}", self);
        HttpResponse::UnprocessableEntity().finish()
    }
}

impl Error for CsrfError {}

/// CSRF middleware to manage CSRF cookies and tokens.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CsrfMiddleware<Rng> {
    inner: Inner<Rng>,
}

impl<Rng: TokenRng + SeedableRng> CsrfMiddleware<Rng> {
    /// Creates a CSRF middleware with secure defaults. Namely:
    ///
    /// - The CSRF cookie will be prefixed with `__Host-`. This also implies the
    /// following:
    ///   - `Secure` is set.
    ///   - `Domain` is _not_ set.
    ///   - `Path` is set to `/`.
    /// - `SameSite` is set to `Strict`.
    /// - `HttpOnly` is set.
    ///
    /// This represents the strictest possible configuration. Requests must be
    /// always sent over HTTPS. Users must explicitly relax these restrictions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<Rng: TokenRng> CsrfMiddleware<Rng> {
    /// Creates a CSRF middleware with secure defaults and the provided Rng.
    /// Namely:
    ///
    /// - The CSRF cookie will be prefixed with `__Host-`. This also implies the
    /// following:
    ///   - `Secure` is set.
    ///   - `Domain` is _not_ set.
    ///   - `Path` is set to `/`.
    /// - `SameSite` is set to `Strict`.
    /// - `HttpOnly` is set.
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

impl<Rng> CsrfMiddleware<Rng> {
    /// Control whether we check for the token on requests.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.inner.csrf_enabled = enabled;
        self
    }

    /// Set a method and path to set a CSRF cookie. This should be all locations
    /// that whose response should set a cookie (via a `Set-Cookie` header) or
    /// those that need the CSRF token value in the response, such as for forms.
    #[must_use]
    pub fn set_cookie<T: Into<String>>(mut self, method: Method, uri: T) -> Self {
        self.inner.set_cookie.insert((method, uri.into()));
        self
    }

    /// Sets the cookie name. Consider using [`host_prefixed_cookie_name`][1] or
    /// [`secure_prefixed_cookie_name`][2] to prefix the cookie name with
    /// `__Host-` or `__Secure-` on your behalf, or prefixing it manually.
    ///
    /// [1]: Self::host_prefixed_cookie_name
    /// [2]: Self::secure_prefixed_cookie_name
    #[must_use]
    pub fn cookie_name<T: Into<String>>(mut self, name: T) -> Self {
        self.inner.cookie_name = Rc::new(name.into());
        self
    }

    /// Sets the cookie name, with `__Host-` automatically prefixed.
    ///
    /// # Examples
    ///
    /// This functionally is equivalent to prefixing the cookie name with
    /// `__Host-`:
    /// ```
    /// use actix_csrf::CsrfMiddleware;
    /// use rand::rngs::StdRng;
    ///
    /// let host_prefixed = CsrfMiddleware::<StdRng>::new()
    ///     .host_prefixed_cookie_name("my_special_cookie");
    /// let manually_prefixed = CsrfMiddleware::<StdRng>::new()
    ///     .cookie_name("__Host-my_special_cookie");
    /// assert_eq!(host_prefixed.cookie_config(), manually_prefixed.cookie_config());
    /// ```
    #[must_use]
    pub fn host_prefixed_cookie_name<T: AsRef<str>>(mut self, name: T) -> Self {
        let mut prefixed = host_prefix!().to_owned();
        prefixed.push_str(name.as_ref());
        self.inner.cookie_name = Rc::new(prefixed);
        self
    }

    /// Sets the cookie name. Consider using [`host_prefixed_cookie_name`][1] or
    /// manually prefixing it with `__Host-` for increased defense-in-depth
    /// measures. This is equivalent to calling
    /// `cookie_name(format!("__Secure-{}", name))`.
    ///
    /// [1]: Self::host_prefixed_cookie_name
    ///
    /// # Examples
    ///
    /// This functionally is equivalent to prefixing the cookie name with
    /// `__Secure-`:
    /// ```
    /// use actix_csrf::CsrfMiddleware;
    /// use rand::rngs::StdRng;
    ///
    /// let host_prefixed = CsrfMiddleware::<StdRng>::new()
    ///     .secure_prefixed_cookie_name("my_special_cookie");
    /// let manually_prefixed = CsrfMiddleware::<StdRng>::new()
    ///     .cookie_name("__Secure-my_special_cookie");
    /// assert_eq!(host_prefixed.cookie_config(), manually_prefixed.cookie_config());
    /// ```
    #[must_use]
    pub fn secure_prefixed_cookie_name<T: AsRef<str>>(mut self, name: T) -> Self {
        let mut prefixed = secure_prefix!().to_owned();
        prefixed.push_str(name.as_ref());
        self.inner.cookie_name = Rc::new(prefixed);
        self
    }

    /// Sets the `SameSite` attribute on the cookie.
    #[must_use]
    pub const fn same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.inner.same_site = same_site;
        self
    }

    /// Sets the `HttpOnly` attribute on the cookie.
    #[must_use]
    pub const fn http_only(mut self, enabled: bool) -> Self {
        self.inner.http_only = enabled;
        self
    }

    /// Sets the `Secure` attribute on the cookie.
    #[must_use]
    pub const fn secure(mut self, enabled: bool) -> Self {
        self.inner.secure = enabled;
        self
    }

    /// Sets the domain of the cookie.
    ///
    /// This will replace the `__Host-` prefix with `__Secure-` instead, if the
    /// cookie name starts with `__Host-` as `__Host-` requires a non-existent
    /// Domain attribute. This weakens a defense-in-depth measure and is not
    /// recommended unless there is an unavoidable need and the security
    /// implications have been fully considered.
    #[must_use]
    pub fn domain<S: Into<String>>(mut self, domain: impl Into<Option<S>>) -> Self {
        if let Some(stripped) = self.inner.cookie_name.strip_prefix(host_prefix!()) {
            self.inner.cookie_name = Rc::new(format!(concat!(secure_prefix!(), "{}"), stripped));
        }
        self.inner.domain = domain.into().map(Into::into);
        self
    }

    /// Produces an CSRF cookie config determined from the current middleware
    /// state. Note that this is **not** needed if you are using default cookie
    /// names.
    #[must_use]
    pub fn cookie_config(&self) -> CsrfCookieConfig {
        CsrfCookieConfig::new((*self.inner.cookie_name).clone())
    }
}

impl<Rng: TokenRng + SeedableRng> Default for CsrfMiddleware<Rng> {
    fn default() -> Self {
        Self {
            inner: Inner::default(),
        }
        .cookie_name(DEFAULT_CSRF_COOKIE_NAME.to_string())
    }
}

impl<S, Rng> Transform<S, ServiceRequest> for CsrfMiddleware<Rng>
where
    S: Service<ServiceRequest, Response = ServiceResponse>,
    Rng: TokenRng + Clone,
{
    type Response = ServiceResponse;
    type Error = S::Error;
    type InitError = ();
    type Transform = CsrfMiddlewareImpl<S, Rng>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(CsrfMiddlewareImpl {
            service,
            inner: self.inner.clone(),
        }))
    }
}

#[doc(hidden)]
pub struct CsrfMiddlewareImpl<S, Rng> {
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
    domain: Option<String>,

    /// If false, will not check at all for CSRF tokens
    csrf_enabled: bool,
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
            domain: None,
            set_cookie: HashSet::new(),
        }
    }

    fn contains(&self, req: &ServiceRequest) -> bool {
        req.match_pattern().map_or_else(
            || {
                self.set_cookie
                    .contains(&(req.method().clone(), req.path().to_string()))
            },
            |p| self.set_cookie.contains(&(req.method().clone(), p)),
        )
    }
}

impl<S, Rng> Service<ServiceRequest> for CsrfMiddlewareImpl<S, Rng>
where
    S: Service<ServiceRequest, Response = ServiceResponse>,
    Rng: TokenRng,
{
    type Response = ServiceResponse;
    type Error = S::Error;
    type Future = CsrfMiddlewareImplFuture<S>;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let cookie = if self.inner.csrf_enabled && self.inner.contains(&req) {
            let token =
                match self.inner.rng.borrow_mut().generate_token() {
                    Ok(token) => token,
                    Err(e) => {
                        error!("Failed to generate CSRF token, aborting request");
                        return CsrfMiddlewareImplFuture::CsrfError(req.error_response(
                            InternalError::new(e, StatusCode::INTERNAL_SERVER_ERROR),
                        ));
                    }
                };

            let cookie = {
                let mut cookie_builder =
                    Cookie::build(self.inner.cookie_name.as_ref(), token.clone())
                        .http_only(self.inner.http_only)
                        .secure(self.inner.secure)
                        .path("/");

                if let Some(same_site) = self.inner.same_site {
                    cookie_builder = cookie_builder.same_site(same_site);
                }

                if let Some(domain) = &self.inner.domain {
                    cookie_builder = cookie_builder.domain(domain);
                }

                cookie_builder.finish()
            };

            let csrf_token = CsrfToken(token);
            req.extensions_mut().insert(csrf_token);

            // The characters allowed in a cookie should be a strict subset
            // of the characters allowed in a header, so this should never
            // fail.
            let header = HeaderValue::from_str(&cookie.to_string())
                .expect("cookie to be a valid header value");

            Some(header)
        } else {
            None
        };

        CsrfMiddlewareImplFuture::Passthrough(Passthrough {
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
pub enum CsrfMiddlewareImplFuture<S: Service<ServiceRequest>> {
    /// A CSRF issue was detected.
    CsrfError(ServiceResponse),
    /// No CSRF issue was detected, so we pass the request through.
    Passthrough(Passthrough<S::Future>),
}

impl<S> Future for CsrfMiddlewareImplFuture<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse>,
{
    type Output = Result<ServiceResponse, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            CsrfMiddlewareImplFuture::CsrfError(error) => {
                // TODO: Find a way to not have to clone.
                let req = error.request().clone();
                let mut new_error = ServiceResponse::new(req, HttpResponse::NoContent().finish());
                std::mem::swap(&mut new_error, error);
                Poll::Ready(Ok(new_error))
            }
            CsrfMiddlewareImplFuture::Passthrough(inner) => match inner.service.as_mut().poll(cx) {
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
    use crate::extractor::{Csrf, CsrfHeader};

    use super::*;

    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::{post, web, App, HttpResponse, Responder};
    use rand::rngs::StdRng;

    fn get_token_from_resp(resp: &ServiceResponse) -> String {
        let cookie = get_cookie_from_resp(resp);
        // should be something like "Csrf-Token=NHMWzEq7nAFZR56jnanhFv6WJdeEAyhy; Path=/"
        let token_header = cookie.split('=');
        let token = token_header.skip(1).take(1).collect::<Vec<_>>()[0];
        let token = token.split(';').next().expect("split to work");
        String::from(token)
    }

    fn get_cookie_from_resp(resp: &ServiceResponse) -> String {
        let cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| value.to_str().expect("header to be valid string"))
            .map(|v| v.split(';').next().expect("split to work"))
            .collect();
        assert_eq!(1, cookie_header.len());
        String::from(*cookie_header.get(0).expect("header to have cookie"))
    }

    fn get_cookie_domain_from_resp(resp: &ServiceResponse) -> String {
        let cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| value.to_str().expect("header to be valid string"))
            .flat_map(|v| v.split(';'))
            .collect();
        String::from(
            cookie_header
                .into_iter()
                .find_map(|s| s.trim().strip_prefix("Domain="))
                .expect("header to have cookie"),
        )
    }

    #[tokio::test]
    async fn attaches_token() {
        let mut srv = test::init_service(
            App::new()
                .wrap(CsrfMiddleware::<StdRng>::new().set_cookie(Method::GET, "/"))
                .service(web::resource("/").to(|| HttpResponse::Ok())),
        )
        .await;
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Cookie should be in the response.
        assert!(get_cookie_from_resp(&resp).contains(DEFAULT_CSRF_COOKIE_NAME));
    }

    #[tokio::test]
    async fn post_request_rejected_without_header() {
        #[post("/")]
        async fn test_route(_: Csrf<CsrfHeader>) -> impl Responder {
            HttpResponse::Ok()
        }

        let mut srv = test::init_service(
            App::new()
                .wrap(CsrfMiddleware::<StdRng>::new())
                .service(test_route),
        )
        .await;

        let resp = test::call_service(&mut srv, TestRequest::post().uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Will use double submit method.
    #[tokio::test]
    async fn double_submit_correct_token() {
        let mut srv = test::init_service(
            App::new()
                .wrap(CsrfMiddleware::<StdRng>::new().set_cookie(Method::GET, "/"))
                .service(
                    web::resource("/")
                        .route(web::get().to(|| HttpResponse::Ok()))
                        .route(web::post().to(|| HttpResponse::Ok())),
                ),
        )
        .await;

        // First, let's get the token as a client.
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/").to_request()).await;

        let token = get_token_from_resp(&resp);
        let cookie = get_cookie_from_resp(&resp);

        // Now we can do another request to a protected endpoint.
        let req = TestRequest::post()
            .uri("/")
            .insert_header(("Cookie", cookie))
            .insert_header((DEFAULT_CSRF_TOKEN_NAME, token))
            .to_request();

        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn domain_attribute_is_set() {
        let mut srv = test::init_service(
            App::new()
                .wrap(
                    CsrfMiddleware::<StdRng>::new()
                        .set_cookie(Method::GET, "/")
                        .domain("example.com"),
                )
                .service(web::resource("/").to(|| HttpResponse::Ok())),
        )
        .await;
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(get_cookie_domain_from_resp(&resp), "example.com");
    }

    #[tokio::test]
    async fn path_info_is_set() {
        let mut srv = test::init_service(
            App::new()
                .wrap(CsrfMiddleware::<StdRng>::new().set_cookie(Method::GET, "/{id}"))
                .service(
                    web::resource("/{id}")
                        .route(web::get().to(|| HttpResponse::Ok()))
                        .route(web::post().to(|| HttpResponse::Ok())),
                ),
        )
        .await;

        // First, let's get the token as a client.
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/1").to_request()).await;

        let token = get_token_from_resp(&resp);
        let cookie = get_cookie_from_resp(&resp);

        // Now we can do another request to a protected endpoint.
        let req = TestRequest::post()
            .uri("/1")
            .insert_header(("Cookie", cookie))
            .insert_header((DEFAULT_CSRF_TOKEN_NAME, token))
            .to_request();

        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
