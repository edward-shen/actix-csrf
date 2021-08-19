# actix-csrf

CSRF middleware for [actix-web] 4.0.0 or newer.

## Mitigation technique

Right now, the middleware will used token-based mitigations. In particular, double token
submit is implemented and I'd like to also use the synchronizer token pattern.

Please take a look at [https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md](here) for a lot of details.
In particular, it describes the conditions in which Double submit cookie is safer:
```
So, unless you are sure that your subdomains are fully secured and only accept HTTPS connections (we believe it’s difficult to guarantee at large enterprises), you should not rely on the Double Submit Cookie technique as a primary mitigation for CSRF.
```

## Usage

Basic usage is

```rust
use actix_csrf::Csrf;
use actix_web::{HttpServer, web, App, HttpResponse};

// switch off during testing to not check CSRF
let enabled = true;

let server = HttpServer::new(move || {
    App::new()
        .wrap(Csrf::new().enable(enabled))
        .service(web::resource("/")
            // by default will not check get
            .route(web::get().to(|| HttpResponse::Ok()))
            // by default will check post
            .route(web::post().to(|| HttpResponse::Ok())))
});
```


## Roadmap

- More flexibility (add whitelist, other ways of extracting token)
- Implement synchronizer token pattern. This will most likely need the session middleware in combinaison with a template language such as askama.
- More testing


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
