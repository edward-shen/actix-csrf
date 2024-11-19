//! This example shows a bare bones example of adding CSRF protection to an image upload
//! HTML form. Remember that these examples are isolated, may not consider all
//! security aspects, such as the strengths and weaknesses of the double-submit
//! technique used.
//!
//! NOTE: This requires the actix-multipart feature to be enabled

use actix_csrf::extractor::{Csrf, CsrfGuarded, CsrfToken};
use actix_csrf::CsrfMiddleware;
use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_web::http::Method;
use actix_web::HttpResponse;
use actix_web::{get, post, App, HttpServer, Responder};
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use openssl::x509::X509;
use rand::prelude::StdRng;

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
            // Our upload form is at `/uploads`, and we want the middleware to set
            // the csrf token when they reach the page. This also lets us access
            // the newly set token with the `CrsfToken` extractor.
            .set_cookie(Method::GET, "/uploads")
            .secure(true); // set the secure attribute to make sure the cookie only gets
                           // transferred over secure channels
        App::new().wrap(csrf).service(upload_ui).service(uploads)
    })
    .bind_openssl(("127.0.0.1", 8443), get_ssl_build())?
    .run()
    .await
}

/// Returns a simple login form with a CSRF token.
#[get("/uploads")]
async fn upload_ui(
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
        <form action="/uploads" method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{}" />
            <label>Images:<input type="file" name="images" accept="image/*" multiple /></label>
            <button type="submit">Upload</button>
        </form>
        </body>
        </html>
        "#,
        token.get()
    );

    HttpResponse::Ok().body(body)
}

#[derive(MultipartForm)]
struct UploadForm {
    csrf_token: Text<CsrfToken>,
    images: Vec<TempFile>,
}

impl CsrfGuarded for UploadForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

/// Validates an uload form that has a CSRF token.
#[post("/uploads")]
async fn uploads(
    // `Csrf` will validate the field with the CSRF token. Since Csrf implements
    // Deref and DerefMut, so you can directly access the actual form data as
    // normal.
    form: Csrf<MultipartForm<UploadForm>>,
) -> impl Responder {
    // At this point, we have a valid CSRF token, so we can treat the request
    // as legitimate.

    // NOTE: Remember that CSRF protections are only effective if there isn't
    // an XSS vector.

    for (idx, _image) in form.images.iter().enumerate() {
        // process the images here
        println!("Image {idx} Processed");
    }

    HttpResponse::Ok().finish()
}
