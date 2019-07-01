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
//! Csrf::new().enable(false);
//! ```
//!
use actix_service::{Service, Transform};
use actix_web::{
    cookie::Cookie,
    dev::ServiceRequest,
    dev::ServiceResponse,
    http::header::{self, HeaderName, HeaderValue},
    http::{Method, StatusCode},
    Error, HttpMessage, HttpResponse, ResponseError,
};
use futures::future::Either;
use futures::future::{ok, FutureResult};
use futures::{Future, Poll};
use log::error;
use std::collections::{HashMap, HashSet};

use failure::Fail;

mod extractor;
mod generator;

/// Internal errors that can happen when processing CSRF tokens.
#[derive(Debug, Fail)]
pub enum CsrfError {
    /// The CSRF Token and the token provided in the headers do not match
    #[fail(display = "The CSRF Tokens do not match")]
    TokenDontMatch,

    /// No CSRF Token in the cookies.
    #[fail(display = "The CSRF Token is missing in the cookies")]
    MissingCookie,

    /// No CSRF Token in the request (headers/body...).
    #[fail(display = "The CSRF Token is missing = {}", _0)]
    MissingToken(String),

    #[fail(display = "Cannot convert header value to string because of non ASCII characters")]
    HeaderBadValue,
}

impl ResponseError for CsrfError {
    fn error_response(&self) -> HttpResponse {
        // I don't really want to leak the error to the client. But I need
        // to log it as CSRF attacks are a thing.
        error!("{}", self);
        HttpResponse::with_body(StatusCode::BAD_REQUEST, format!("CSRF Error").into())
    }
}

/// Middleware builder. The default will check CSRF on every request but
/// GET and POST. You can specify whether to disable.
pub struct Csrf {
    /// Control whether or not we check the CSRF token.
    enabled: bool,

    /// Extract the token from an incoming HTTP request. One extractor
    /// per Method.
    req_extractors: HashMap<Method, Box<extractor::Extractor>>,

    /// Endpoints that are not protected by the middleware.
    /// combinaison of Method and URI.
    whitelist: Vec<(Method, String)>,
}

impl Csrf {
    /// Create the CSRF default middleware
    pub fn new() -> Self {
        // sane defaults?
        let mut req_extractors: HashMap<Method, Box<extractor::Extractor>> = HashMap::new();
        req_extractors.insert(
            Method::POST,
            Box::new(extractor::BasicExtractor::Header {
                name: "x-csrf-token".to_owned(),
            }),
        );

        req_extractors.insert(
            Method::PUT,
            Box::new(extractor::BasicExtractor::Header {
                name: "x-csrf-token".to_owned(),
            }),
        );

        req_extractors.insert(
            Method::DELETE,
            Box::new(extractor::BasicExtractor::Header {
                name: "x-csrf-token".to_owned(),
            }),
        );

        Self {
            enabled: true,
            req_extractors,
            whitelist: vec![],
        }
    }

    /// Control whether we check for the token on requests.
    pub fn enable(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn extractor(mut self, method: Method, extractor: Box<extractor::Extractor>) -> Self {
        self.req_extractors.insert(method, extractor);
        self
    }
}

// Middleware factory is `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S> for Csrf
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CsrfMiddleware<S>;
    type Future = FutureResult<Self::Transform, Self::InitError>;

    fn new_transform(&self, service: S) -> Self::Future {
        let cookie_name = String::from("csrfToken");

        ok(CsrfMiddleware {
            service,
            inner: Inner {
                generator: Box::new(generator::RandGenerator::new()),
                cookie_name,
                csrf_enabled: self.enabled,
                req_extractors: self.req_extractors.clone(),
                whitelist: vec![],
            },
        })
    }
}

pub struct CsrfMiddleware<S> {
    service: S,
    inner: Inner,
}

struct Inner {
    /// To generate the token
    generator: Box<generator::Generator>,

    cookie_name: String,

    /// If false, will not check at all for CSRF tokens
    csrf_enabled: bool,

    /// Extract the token from an incoming HTTP request. One extractor
    /// per Method.
    req_extractors: HashMap<Method, Box<extractor::Extractor>>,

    /// Endpoints that are not protected by the middleware.
    /// combinaison of Method and URI.
    whitelist: Vec<(Method, String)>,
}

impl Inner {
    /// Will return true if the middleware needs to check the CSRF tokens.
    fn should_protect(&self, req: &ServiceRequest) -> bool {
        (self.req_extractors.contains_key(req.method())) && self.csrf_enabled
    }

    /// Generate the next token
    fn generate_token(&mut self) -> String {
        self.generator.generate_token()
    }

    /// Will extract the token from a cookie that was set previously.
    fn extract_cookie_token(&self, req: &ServiceRequest) -> Result<String, CsrfError> {
        req.cookie(&self.cookie_name)
            .map(|cookie| cookie.value().to_string())
            .ok_or(CsrfError::MissingCookie)
    }

    /// Will extract the matching token from the request.
    fn extract_request_token(&self, req: &ServiceRequest) -> Result<String, CsrfError> {
        // Unwrap. At this point, if we arrive here, there is no doubt we have
        // an extractor or it means there is a coding error.
        self.req_extractors
            .get(&req.method())
            .unwrap()
            .extract_token(&req)
    }
}

impl<S, B> Service for CsrfMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Either<
        FutureResult<Self::Response, Error>,
        Box<Future<Item = Self::Response, Error = Self::Error>>,
    >;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        self.service.poll_ready()
    }

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
                (Err(e), Ok(_)) | (Ok(_), Err(e)) => return Either::A(ok(req.error_response(e))),
                (Err(e), Err(_)) => return Either::A(ok(req.error_response(e))),
                (Ok(ref cookie_token), Ok(ref req_token)) if cookie_token != req_token => {
                    println!("COOKIE {:?} HEADER {:?}", cookie_token, req_token);
                    return Either::A(ok(req.error_response(CsrfError::TokenDontMatch)));
                }
                _ => (),
            }
        }

        // TODO Lifetime issue when I put that in and_then
        let token = self.inner.generate_token();
        let cookie_name = self.inner.cookie_name.clone();
        let enabled = self.inner.csrf_enabled.clone();

        Either::B(Box::new(self.service.call(req).and_then(move |mut res| {
            // Set the newly generated token.
            let mut cookie = Cookie::new(cookie_name, token);
            cookie.set_path("/");

            if enabled {
                res.headers_mut().insert(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&cookie.to_string()).unwrap(),
                );
            }
            Ok(res)
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::{web, App, HttpResponse};

    fn get_token_from_resp(resp: &ServiceResponse) -> String {
        // Cookie should be in the response.
        let mut cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| String::from(value.to_str().unwrap()))
            .collect();
        assert_eq!(1, cookie_header.len());
        assert!(cookie_header.get(0).unwrap().contains("csrfToken"));

        // should be something like "csrfToken=NHMWzEq7nAFZR56jnanhFv6WJdeEAyhy; Path=/"
        println!("{:?}", cookie_header.get(0).unwrap());
        let token_header: String = cookie_header.get(0).take().unwrap().to_string();
        let token = &token_header[10..42];
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
    #[test]
    fn test_attach_token() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new())
                .service(web::resource("/").to(|| HttpResponse::Ok())),
        );
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/").to_request());
        assert_eq!(resp.status(), StatusCode::OK);

        // Cookie should be in the response.
        let cookie_header: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(header_name, _)| header_name.as_str() == "set-cookie")
            .map(|(_, value)| String::from(value.to_str().unwrap()))
            .collect();
        assert_eq!(1, cookie_header.len());
        assert!(cookie_header.get(0).unwrap().contains("csrfToken"));
    }

    // With default protection, POST requests is rejected.
    #[test]
    fn test_post_request_rejected() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new())
                .service(web::resource("/").route(web::post().to(|| HttpResponse::Ok()))),
        );
        let resp = test::call_service(&mut srv, TestRequest::post().uri("/").to_request());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Can disable protection for unit tests.
    #[test]
    fn test_post_accepted_with_disabled() {
        let mut srv = test::init_service(
            App::new()
                .wrap(Csrf::new().enable(false))
                .service(web::resource("/").route(web::post().to(|| HttpResponse::Ok()))),
        );
        let resp = test::call_service(&mut srv, TestRequest::post().uri("/").to_request());
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
    #[test]
    fn double_submit_correct_token() {
        let mut srv = test::init_service(
            App::new().wrap(Csrf::new()).service(
                web::resource("/")
                    .route(web::get().to(|| HttpResponse::Ok()))
                    .route(web::post().to(|| HttpResponse::Ok())),
            ),
        );

        // First, let's get the token as a client.
        let resp = test::call_service(&mut srv, TestRequest::with_uri("/").to_request());

        let token = get_token_from_resp(&resp);
        let cookie = get_cookie_from_resp(&resp);

        // Now we can do another request to a protected endpoint.
        let req = TestRequest::post()
            .uri("/")
            .header("cookie", cookie)
            .header("x-csrf-token", token)
            .to_request();
        let resp = test::call_service(&mut srv, req);
        assert_eq!(resp.status(), StatusCode::OK);
    }

}
