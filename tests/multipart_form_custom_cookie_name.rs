#![cfg(test)]
#![cfg(feature = "actix-multipart")]

use std::str::FromStr;

use actix_csrf::extractor::{Csrf, CsrfCookieConfig, CsrfGuarded, CsrfToken};
use actix_csrf::CsrfMiddleware;

use actix_http::{Request, StatusCode};
use actix_multipart::form::{text::Text, MultipartForm};
use actix_multipart::test::create_form_data_payload_and_headers;
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::SET_COOKIE;
use actix_web::http::Method;
use actix_web::test::{call_service, init_service, TestRequest};
use actix_web::HttpResponse;
use actix_web::{get, post, App, Responder};
use anyhow::{Context, Result};
use cookie::Cookie;
use rand::prelude::StdRng;

#[actix_web::test]
async fn get_request_returns_double_token() -> Result<()> {
    let csrf = CsrfMiddleware::<StdRng>::new()
        .set_cookie(Method::GET, "/login")
        .cookie_name("Custom-Cookie-Name");
    let service = init_service(
        App::new()
            .app_data(CsrfCookieConfig::new("Custom-Cookie-Name".to_owned()))
            .wrap(csrf)
            .service(request_csrf),
    )
    .await;

    let (resp, cookie) = get_cookie(&service).await?;

    assert_eq!(cookie.value(), resp.into_body().try_into_bytes().unwrap());

    Ok(())
}

async fn get_cookie<S, E>(service: &S) -> Result<(ServiceResponse, Cookie<'static>)>
where
    S: Service<Request, Response = ServiceResponse<BoxBody>, Error = E>,
    E: std::fmt::Debug,
{
    let req = TestRequest::with_uri("/login").to_request();
    let resp = call_service(&service, req).await;
    let set_cookie_header = resp
        .headers()
        .get(SET_COOKIE)
        .context("set cookie header missing")?
        .to_str()
        .context("csrf token not base64")?;
    let cookie = Cookie::from_str(set_cookie_header)?;
    Ok((resp, cookie.into_owned()))
}

#[actix_web::test]
async fn post_request_is_guarded() -> Result<()> {
    let csrf = CsrfMiddleware::<StdRng>::new()
        .set_cookie(Method::GET, "/login")
        .cookie_name("Custom-Cookie-Name");
    let service = init_service(
        App::new()
            .app_data(CsrfCookieConfig::new("Custom-Cookie-Name".to_owned()))
            .wrap(csrf)
            .service(request_csrf)
            .service(upload),
    )
    .await;

    let (_, cookie) = get_cookie(&service).await?;

    // create multipart form data with CSRF token
    let (body, headers) = create_form_data_payload_and_headers(
        "csrf_token",
        None,
        Some(mime::TEXT_PLAIN_UTF_8),
        cookie.clone().value().to_owned().into(),
    );

    let req = TestRequest::post();
    let req = headers
        .into_iter()
        .fold(req, |req, hdr| req.insert_header(hdr))
        .uri("/uploads")
        .cookie(cookie.clone())
        .set_payload(body)
        .to_request();

    let resp = call_service(&service, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[actix_web::test]
async fn custom_cookie_name_shortcut_works() -> Result<()> {
    let csrf = CsrfMiddleware::<StdRng>::new()
        .set_cookie(Method::GET, "/login")
        .cookie_name("Custom-Cookie-Name");
    let service = init_service(
        App::new()
            .app_data(csrf.cookie_config())
            .wrap(csrf)
            .service(request_csrf)
            .service(upload),
    )
    .await;

    let (_, cookie) = get_cookie(&service).await?;

    // create multipart form data with CSRF token
    let (body, headers) = create_form_data_payload_and_headers(
        "csrf_token",
        None,
        Some(mime::TEXT_PLAIN_UTF_8),
        cookie.clone().value().to_owned().into(),
    );

    let req = TestRequest::post();
    let req = headers
        .into_iter()
        .fold(req, |req, hdr| req.insert_header(hdr))
        .uri("/uploads")
        .cookie(cookie.clone())
        .set_payload(body)
        .to_request();

    let resp = call_service(&service, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

/// Returns a simple login form with a CSRF token.
#[get("/login")]
async fn request_csrf(token: CsrfToken) -> impl Responder {
    HttpResponse::Ok().body(token.into_inner())
}

#[derive(MultipartForm)]
struct UploadForm {
    csrf_token: Text<CsrfToken>,
}

impl CsrfGuarded for UploadForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

#[post("/uploads")]
async fn upload(_: Csrf<MultipartForm<UploadForm>>) -> impl Responder {
    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.
    HttpResponse::Ok().finish()
}
