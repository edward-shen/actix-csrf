//! This example shows a bare bones example of adding CSRF protection to a JSON
//! endpoint by adding a CSRF field to the JSON request. Remember that these
//! examples are isolated, may not consider all security aspects, such as the
//! strengths and weaknesses of the double-submit technique used.

use actix_csrf::extractor::{Csrf, CsrfGuarded, CsrfToken};
use actix_csrf::CsrfMiddleware;
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
            CsrfMiddleware::<StdRng>::new()
            // We need to disable HttpOnly, or else we can't access the cookie
            // from Javascript.
            .http_only(false)
            // Our login form is at `/login`, and we want the middleware to set
            // the csrf token when they reach the page. This also lets us access
            // the newly set token with the `CrsfToken` extractor.
            .set_cookie(Method::GET, "/login");

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
                },
                // Set the CSRF token in the request body.
                body: JSON.stringify({
                    csrf: csrfValue,
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
    csrf: CsrfToken,
    count: usize,
}

impl CsrfGuarded for Request {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf
    }
}

#[derive(Serialize)]
struct Response {
    count: usize,
}

/// Validates a json endpoint that has a CSRF token.
#[post("/login")]
async fn login(
    // `Csrf` will validate the field with the CSRF token. Since Csrf implements
    // Deref and DerefMut, so you can directly access the actual form data as
    // normal.
    json: Csrf<Json<Request>>,
) -> impl Responder {
    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.

    // NOTE: Remember that CSRF protections are only effective if there isn't
    // an XSS vector.

    HttpResponse::Ok().json(Response {
        count: json.count + 1,
    })
}
