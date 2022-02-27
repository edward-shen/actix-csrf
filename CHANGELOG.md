# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.5.0 - 2022-02-26

- Specify no default features for dependencies.
- Updated for `actix-web` v4.0.0

## 0.4.0 - 2021-12-04

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