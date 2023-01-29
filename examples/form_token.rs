//! This example shows a bare bones example of adding CSRF protection to an HTML
//! form. Remember that these examples are isolated, may not consider all
//! security aspects, such as the strengths and weaknesses of the double-submit
//! technique used.

use actix_csrf::extractor::{Csrf, CsrfGuarded, CsrfToken};
use actix_csrf::CsrfMiddleware;
use actix_web::http::Method;
use actix_web::web::Form;
use actix_web::HttpResponse;
use actix_web::{get, post, App, HttpServer, Responder};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod},
    x509::X509,
};
use rand::prelude::StdRng;
use serde::Deserialize;
use tracing::info;

fn get_ssl_build() -> SslAcceptorBuilder {
    let key = include_bytes!("key/server.pem");
    let key = PKey::private_key_from_pem(key).unwrap();

    let cert = include_bytes!("key/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key(key.as_ref()).unwrap();
    builder.set_certificate(cert.as_ref()).unwrap();

    builder
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let csrf =
            // Use the default CSRF token settings. Among other protections,
            // this means that the CSRF token is inaccessible to Javascript.
            CsrfMiddleware::<StdRng>::new()
            // Our login form is at `/login`, and we want the middleware to set
            // the csrf token when they reach the page. This also lets us access
            // the newly set token with the `CrsfToken` extractor.
            .set_cookie(Method::GET, "/login");
        App::new().wrap(csrf).service(login_ui).service(login)
    })
    .bind_openssl(("127.0.0.1", 8443), get_ssl_build())?
    .run()
    .await
}

/// Returns a simple login form with a CSRF token.
#[get("/login")]
async fn login_ui(
    // `CsrfToken` is an extractor that provides access to the CSRF token that
    // will be set by the middleware. Note that this is only accessible since
    // we previously called `.set_cookie` on this endpoint.
    token: CsrfToken,
) -> impl Responder {
    let body = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Example</title></head>
        <body>
        <form action="/login" method="post">
            <input type="hidden" name="csrf_token" value="{}" />
            <label>Username:<input type="text" name="username" /></label>
            <label>Password:<input type="password" name="password" /></label>
            <button type="submit">Login</button>
        </form>
        </body>
        </html>
        "#,
        token.get()
    );

    HttpResponse::Ok().body(body)
}

#[derive(Deserialize)]
struct LoginForm {
    csrf_token: CsrfToken,
    username: String,
    password: String,
}

impl CsrfGuarded for LoginForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

/// Validates a login form that has a CSRF token.
#[post("/login")]
async fn login(
    // `Csrf` will validate the field with the CSRF token. Since Csrf implements
    // Deref and DerefMut, so you can directly access the actual form data as
    // normal.
    form: Csrf<Form<LoginForm>>,
) -> impl Responder {
    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.

    // NOTE: Remember that CSRF protections are only effective if there isn't
    // an XSS vector.

    // check credentials
    if form.username == "foo" && form.password == "bar" {
        info!("foo logged in!");
    }

    HttpResponse::Ok().finish()
}
