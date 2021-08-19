# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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