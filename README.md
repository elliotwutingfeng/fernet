# fernet

[![Pub Package](https://img.shields.io/pub/v/fernet?style=for-the-badge)](https://pub.dev/packages/fernet)
[![Coveralls](https://img.shields.io/coverallsCoverage/github/elliotwutingfeng/fernet?logo=coveralls&style=for-the-badge)](https://coveralls.io/github/elliotwutingfeng/fernet?branch=main)
[![LICENSE](https://img.shields.io/badge/LICENSE-BSD--3--Clause-GREEN?style=for-the-badge)](LICENSE)

A Dart library for encrypting and decrypting messages using the [Fernet](https://cryptography.io/en/latest/fernet) scheme.

This is a direct port of the Fernet implementation in the Python [cryptography](https://cryptography.io) library.

## Requirements

- **Dart SDK:** 3.0+

## Using passwords with Fernet

It is possible to use passwords with Fernet. To do this, you need to run the password through a key derivation function such as PBKDF2HMAC, bcrypt, scrypt, or argon2. An example with argon2id is provided at [example/password.dart](example/password.dart).

## Implementation

Fernet is built on top of a number of standard cryptographic primitives. Specifically it uses:

- AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding.

- HMAC using SHA256 for authentication.

- Initialization vectors are generated using Random.secure().

For complete details consult the [specification](https://github.com/fernet/spec/blob/master/Spec.md).

The cryptographic primitives used in this library are provided by [pointycastle](https://pub.dev/packages/pointycastle).

## Limitations

Fernet is ideal for encrypting data that easily fits in memory. As a design feature it does not expose unauthenticated bytes. This means that the complete message contents must be available in memory, making Fernet generally unsuitable for very large files at this time.

## Credits

This library uses code from other open-source projects. The copyright statements of these open-source projects are listed in [CREDITS.md](CREDITS.md). Most of the documentation and implementation details have been adapted from the Python [cryptography](https://cryptography.io) library.
