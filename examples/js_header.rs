//! This example shows a bare bones example of adding CSRF protection to a JSON
//! endpoint by adding a custom header. Remember that these examples are
//! isolated, may not consider all security aspects, such as the strengths and
//! weaknesses of the double-submit technique used.

use actix_csrf::extractor::{CsrfCookie, CsrfHeader};
use actix_csrf::Csrf;
use actix_web::http::Method;
use actix_web::web::Json;
use actix_web::HttpResponse;
use actix_web::{get, post, App, HttpServer, Responder};
use rand::prelude::StdRng;
use serde::{Deserialize, Serialize};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let csrf =
            // Use the default CSRF token settings. Among other protections,
            // this means that the CSRF token is inaccessible to Javascript.
            Csrf::<StdRng>::new()
            // We need to disable HttpOnly, or else we can't access the cookie
            // from Javascript.
            .http_only(false)
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
async fn login_ui() -> impl Responder {
    let body = r#"
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Example</title></head>
        <body>
        <script>
        function submit() {
            // Get the CSRF value from our cookie.
            const csrfValue = document.cookie.split("=")[1];
            let request = new Request("/login", {
                method: "POST",
                // Actix strictly requires the content type to be set.
                headers: {
                    "Content-Type": "application/json",
                    "Csrf-Token": csrfValue,
                },
                // Set the CSRF token in the request body.
                body: JSON.stringify({
                    count: 0,
                })
            });
            fetch(request)
                .then(resp => resp.json())
                .then(resp => console.log(resp.count));
        }
        </script>
        <button onclick="submit()">Click me!</button>
        </body>
        </html>
        "#;

    HttpResponse::Ok().body(body)
}

#[derive(Deserialize)]
struct Request {
    count: usize,
}

#[derive(Serialize)]
struct Response {
    count: usize,
}

/// Validates a json endpoint that has a CSRF token.
#[post("/login")]
async fn login(
    // This is a simple extractor that provides access to the CSRF cookie. If
    // preferred, you can simply extract it from the headers yourself, but this
    // has the added benefit of acting as a resource guard. Requests without a
    // CSRF cookie will be rejected.
    cookie: CsrfCookie,
    csrf_header: CsrfHeader,
    json: Json<Request>,
) -> impl Responder {
    // As inputs for the double submit pattern heavily varies, the middleware
    // will not validate automatically validate CSRF tokens by itself. Callers
    // should validate this manually, as shown.
    if !cookie.validate(csrf_header.as_ref()) {
        return HttpResponse::BadRequest().finish();
    }

    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.

    // NOTE: Remember that CSRF protections are only effective if there isn't
    // an XSS vector.

    HttpResponse::Ok().json(Response {
        count: json.count + 1,
    })
}
