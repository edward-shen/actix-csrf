//! This example shows a bare bones example of adding CSRF protection to an HTML
//! form. Remember that these examples are isolated, may not consider all
//! security aspects, such as the strengths and weaknesses of the double-submit
//! technique used.

use actix_csrf::extractor::{CsrfCookie, CsrfToken};
use actix_csrf::Csrf;
use actix_web::http::Method;
use actix_web::web::Form;
use actix_web::HttpResponse;
use actix_web::{get, post, App, HttpServer, Responder};
use rand::prelude::StdRng;
use serde::Deserialize;
use tracing::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let csrf =
            // Use the default CSRF token settings. Among other protections,
            // this means that the CSRF token is inaccessible to Javascript.
            Csrf::<StdRng>::new()
            // Our login form is at `/login`, and we want the middleware to set
            // the csrf token when they reach the page. This also lets us access
            // the newly set token with the `CrsfToken` extractor.
            .set_cookie(Method::GET, "/login")
            // This requires that a POST request to `/login` MUST have a CSRF
            // token set. This effectively acts like a guard, rejecting requests
            // that don't have the CSRF cookie set.
            .validate_cookie(Method::POST, "/login");

        App::new().wrap(csrf).service(login_ui).service(login)
    })
    .bind(("127.0.0.1", 8080))?
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
        <head><title>Example</title></head>
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
    csrf_token: String,
    username: String,
    password: String,
}

/// Validates a login form that has a CSRF token.
#[post("/login")]
async fn login(
    // This is a simple extractor that provides access to the CSRF cookie. If
    // preferred, you can simply extract it from the headers yourself, but this
    // has the added benefit of acting as a resource guard. Requests without a
    // CSRF cookie will be rejected.
    cookie: CsrfCookie,
    form: Form<LoginForm>,
) -> impl Responder {
    // As inputs for the double submit pattern heavily varies, the middleware
    // will not validate automatically validate CSRF tokens by itself. Callers
    // should validate this manually, as shown.
    if !cookie.validate(&form.csrf_token) {
        return HttpResponse::BadRequest().finish();
    }

    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.
    //
    // NOTE: Remember that CSRF protections are only effective if there isn't
    // an XSS vector.

    // check credentials
    if form.username == "foo" && form.password == "bar" {
        info!("foo logged in!");
    }

    HttpResponse::Ok().finish()
}
