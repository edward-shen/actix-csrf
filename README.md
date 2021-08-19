# actix-csrf

CSRF middleware for [actix-web] 4.0.0 or newer that uses the Double-Submit Token
pattern.

_This crate has not yet been audited. Use in production at your own risk._

## Usage

Installing the middleware is standard: Specify a cryptographically secure RNG to
use, and declare which paths should set a CSRF cookie and when should validate a
CSRF cookie.

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let csrf = Csrf::<StdRng>::new()
            .set_cookie(Method::GET, "/login")
            .validate_cookie(Method::POST, "/login");
        App::new().wrap(csrf).service(login_ui).service(login)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Then, use the `CsrfCookie` extractor to pull the CSRF cookie and validate it
with a CSRF token provided as part of the protected request.

```rust
#[derive(Deserialize)]
struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

/// Validates a login form that has a CSRF token.
#[post("/login")]
async fn login(cookie: CsrfCookie, form: Form<LoginForm>) -> impl Responder {
    // As inputs for the double submit pattern heavily varies, the middleware
    // will not validate automatically validate CSRF tokens by itself. Callers
    // should validate this manually, as shown.
    if !cookie.validate(&form.csrf_token) {
        return HttpResponse::BadRequest().finish();
    }

    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.

    HttpResponse::Ok().finish()
}
```

This is only one of many ways to use the Double-Submit Token pattern; see the
[docs] and [examples](examples) for more information.

## Security Considerations

There are advantages and limitations to using the Double Submit Token pattern.
Users are highly recommended to read the [Owasp article on CSRF Protection][csrf]
before using this middleware.

This crate attempts to have secure defaults, and users must explicitly disable
defense-in-depth features.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[actix-web]: https://github.com/actix/actix-web
[docs]: https://docs.rs/actix-csrf/latest/actix_csrf/
[csrf]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html