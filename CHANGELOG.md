# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 - 2022-09-04

### Added

- Added `Crsf::into_inner` (#6; thanks @Conni2461)

### Changed

- Since `actix-web` was updated to 4.1.0, the MSRV was changed to 1.59.
`actix-csrf` will follow `actix-web` and will build against 1.59.

### Fixed

- Routes with path info will properly be matched against a CRSF token (#8;
thanks @Conni2461)

## 0.6.1 - 2022-05-25

### Added

- Added `CsrfMiddleware::host_prefixed_cookie_name` and
`CsrfMiddleware::secure_prefixed_cookie_name`.
- Added `CsrfMiddleware::cookie_config` to help create a `CsrfCookieConfig` from
the current middleware state. This primarily is useful if the cookie name was
changed.
- Added `CsrfMiddleware::domain`, which sets the `Domain` attribute of the set
cookie and downgrades the `__Host-` prefix to `__Secure-` if it exists.

### Changed

- Fixed `CsrfMiddleware` constructor docs.
- Fixed `CsrfCookieConfig` docs.
- `actix-csrf` compiles with Rust 1.54.0. This is not a guarantee, but a best
effort attempt.

## 0.6.0 - 2022-04-10

### Added

- Added constructors for `CsrfCookieConfig` and `CsrfHeaderConfig`.

### Changed

- Updated `cookie` to v0.16.

## 0.5.0 - 2022-02-26

### Changed

- Specify no default features for dependencies.
- Updated for `actix-web` v4.0.0

## 0.4.0 - 2021-12-04

### Changed

- Updated for `actix-web` v4.0.0-beta.13

## 0.3.0 - 2021-08-22

### Added

- A `Csrf` extractor that wraps around other extractors has been added. in
conjunction with the `CsrfGuarded` trait, this provides a difficult to misuse
API over the implementation in previous versions.

### Changed

- `Csrf` is now named `CsrfMiddleware`.
- `CsrfMiddleware` no longer validates requests; that functionality has been
moved to the `Csrf` extractor.
- `CsrfMiddleware::set_cookie` and `CsrfMiddleware::cookie_name` now accept a
- `impl Into<String>` instead of `impl ToString`.
- `actix_csrf` now depends on `serde` and no longer has a `serde` feature.
- `TokenRng` has been moved to the crate root.

## 0.2.2 - 2021-08-19

### Fixed

- `Serialize` and `Deserialize` are now properly imported.

## 0.2.1 - 2021-08-19

### Added

- Users can now specify the `serde` feature, which currently only implements
`Serialize` and `Deserialize` for `CsrfToken`.

## 0.2.0 - 2021-08-18

### Changes

- Updated `actix-csrf` to be compatible with `actix` versions 4.0.0 or newer.
