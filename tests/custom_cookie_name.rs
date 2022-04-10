#![cfg(test)]

use std::str::FromStr;

use actix_csrf::extractor::{Csrf, CsrfCookieConfig, CsrfGuarded, CsrfToken};
use actix_csrf::CsrfMiddleware;

use actix_http::{Request, StatusCode};
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::SET_COOKIE;
use actix_web::http::Method;
use actix_web::test::{call_service, init_service, TestRequest};
use actix_web::web::Form;
use actix_web::HttpResponse;
use actix_web::{get, post, App, Responder};
use anyhow::{Context, Result};
use cookie::Cookie;
use rand::prelude::StdRng;
use serde::{Deserialize, Serialize};

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
            .service(login),
    )
    .await;

    let (_, cookie) = get_cookie(&service).await?;

    let req = TestRequest::post()
        .uri("/login")
        .cookie(cookie.clone())
        .set_form(LoginForm {
            csrf_token: CsrfToken::test_create(cookie.value().to_owned()),
        })
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

#[derive(Serialize, Deserialize)]
struct LoginForm {
    csrf_token: CsrfToken,
}

impl CsrfGuarded for LoginForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

#[post("/login")]
async fn login(_: Csrf<Form<LoginForm>>) -> impl Responder {
    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.
    HttpResponse::Ok().finish()
}
