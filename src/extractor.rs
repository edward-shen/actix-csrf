//! Extractor are used to extract the CSRF token.
//!
//! The token can be stored in different ways (POST body, headers,
//! GET params, session...).
//!
//! Basic extractors are provided:
//! - from header
//! - from cookie
//! - from url parameters
//!
//! You can use the trait `Extractor` to add a custom extractor.

use crate::CsrfError;
use actix_web::dev::ServiceRequest;
use actix_web::HttpMessage;

/// Trait to extract token from a request.
pub trait Extractor: ExtractorClone {
    fn extract_token(&self, msg: &ServiceRequest) -> Result<String, CsrfError>;
}

// https://stackoverflow.com/questions/30353462/how-to-clone-a-struct-storing-a-boxed-trait-object/30353928#30353928
pub trait ExtractorClone {
    fn clone_box(&self) -> Box<Extractor>;
}

impl<T> ExtractorClone for T
where
    T: 'static + Extractor + Clone,
{
    fn clone_box(&self) -> Box<Extractor> {
        Box::new(self.clone())
    }
}

impl Clone for Box<Extractor> {
    fn clone(&self) -> Box<Extractor> {
        self.clone_box()
    }
}

#[derive(Debug, Clone)]
pub enum BasicExtractor {
    /// Extract from a cookie
    Cookie { name: String },

    /// Extract from the request headers
    Header { name: String },
}

impl Extractor for BasicExtractor {
    fn extract_token(&self, msg: &ServiceRequest) -> Result<String, CsrfError> {
        match *self {
            BasicExtractor::Cookie { ref name } => msg
                .cookie(name)
                .map(|cookie| cookie.value().to_string())
                .ok_or(CsrfError::MissingToken(format!("from {} cookie", name))),
            BasicExtractor::Header { ref name } => {
                for (header_name, value) in msg.headers() {
                    if header_name.as_str() == name.as_str() {
                        let str_v = value.to_str().unwrap();
                        return Ok(String::from(str_v));
                    }
                }

                Err(CsrfError::MissingToken(format!("from {} header", name)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::http::header;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::{web, App, HttpResponse};

    #[test]
    fn extract_from_header() {
        let extractor = BasicExtractor::Header {
            name: String::from("csrf"),
        };

        let req = TestRequest::with_header("csrf", "sometoken").to_srv_request();
        let token = extractor.extract_token(&req);

        assert!(token.is_ok());
        assert_eq!("sometoken", token.unwrap().as_str());
    }

    #[test]
    fn not_found_header() {
        let extractor = BasicExtractor::Header {
            name: String::from("csrf"),
        };

        let req = TestRequest::with_header("fake", "sometoken").to_srv_request();
        let token = extractor.extract_token(&req);

        assert!(token.is_err());
        let err = token.err().unwrap();
        assert_eq!(
            "The CSRF Token is missing = from csrf header",
            format!("{}", err)
        );
    }

    #[test]
    fn extract_from_cookie() {
        let req = TestRequest::with_header(header::COOKIE, "csrf=sometoken").to_srv_request();

        let extractor = BasicExtractor::Cookie {
            name: String::from("csrf"),
        };

        let token = extractor.extract_token(&req);
        assert!(token.is_ok());
        assert_eq!("sometoken", token.unwrap().as_str())
    }

    #[test]
    fn not_found_cookie() {
        let extractor = BasicExtractor::Header {
            name: String::from("csrf"),
        };

        let req = TestRequest::with_header("fake", "sometoken").to_srv_request();
        let token = extractor.extract_token(&req);

        assert!(token.is_err());
        let err = token.err().unwrap();
        assert_eq!(
            "The CSRF Token is missing = from csrf header",
            format!("{}", err)
        );
    }

}
