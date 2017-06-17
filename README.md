# JSON Web Token [![travis][ci_img]][travis] [![yard docs][yd_img]][yard_docs] [![code climate][cc_img]][code_climate]

## A JSON Web Token (JWT) implementation for Ruby

### Description
A Ruby implementation of the JSON Web Token standard [RFC 7519][rfc7519]

## Installation
    gem install json_web_token

### Philosophy & Design Goals
* Minimal API surface area
* Clear separation and conformance to underlying standards
  - JSON Web Signature (JWS) Standards Track [RFC 7515][rfc7515]
  - JSON Web Algorithms (JWA) Standards Track [RFC 7518][rfc7518]
* Thorough test coverage
* Modularity for comprehension and extensibility
* Fail fast and hard, with maximally strict validation
  - Inspired by [The Harmful Consequences of Postel's Maxim][thomson-postel]
* Implement only the REQUIRED elements of the JWT standard (initially)

### Intended Audience
Token authentication of API requests to Rails via these prominent gems:

- [Devise][devise]
- [Doorkeeper][doorkeeper]
- [OAuth2][oauth2]

Secure Cross-Origin Resource Sharing ([CORS][cors]) using the [rack-cors][rack-cors] gem

### Support for JWT Registered Claims

Support for the standard registered claims documented
in [RFC 7519][rfc7519] can be found in the companion gem [jwt_claims](https://github.com/garyf/jwt_claims).

`jwt_claims` is a wrapper around `json_web_token` and provides support
for the full set of registered claims.

[https://github.com/garyf/jwt_claims](https://github.com/garyf/jwt_claims)

## Usage

### JsonWebToken.sign(claims, options)

Returns a JSON Web Token string

`claims` (required) string or hash

`options` (required) hash

* **alg** (optional, default: `HS256`)
* **key** (required unless alg is 'none')

Example

```ruby
require 'json_web_token'

# Sign with the default algorithm, HMAC SHA256
jwt = JsonWebToken.sign({foo: 'bar'}, key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C')
#=> "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.vpaYTGkypBmxDi3KZYcvpqLx9xqhRD-DSXONGrUbf5Q"

# Sign with RSA SHA256 algorithm
opts = {
  alg: 'RSA256',
  key: < RSA private key >
}

jwt = JsonWebToken.sign({foo: 'bar'}, opts)

# Create an unsecured token (algorithm is 'none')
jwt = JsonWebToken.sign({foo: 'bar'}, alg: 'none')

```

### JsonWebToken.verify(jwt, options)

Returns a hash:
* \{ok: < JWT claims set >\}, if the Message Authentication Code (MAC), or signature, is verified
* \{error: 'invalid'\}, otherwise

`jwt` (required) is a JSON web token string

`options` (required) hash

* **alg** (optional, default: `HS256`)
* **key** (required unless alg is 'none')

Example

```ruby
require 'json_web_token'

jwt = JsonWebToken.sign({foo: 'bar'}, key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C')
#=> "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.vpaYTGkypBmxDi3KZYcvpqLx9xqhRD-DSXONGrUbf5Q"

# Verify with default algorithm, HMAC SHA256
# Returns a hash of `{:ok, verified_claims}`
JsonWebToken.verify(jwt, key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C')
#=> {:ok=>{:foo=>"bar"}}

# verify with RSA SHA256 algorithm
opts = {
  alg: 'RSA256',
  key: < RSA public key >
}

{ok: claims} = JsonWebToken.verify(jwt, opts)

# Unsecured token (algorithm is 'none')
jwt = JsonWebToken.sign({foo: 'bar'}, alg: 'none')
#=> "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ."

JsonWebToken.verify(jwt, alg: 'none')
#=> {:ok=>{:foo=>"bar"}}
```

### Supported encryption algorithms

alg Param Value | Digital Signature or MAC Algorithm
------|------
HS256 | HMAC using SHA-256 per [RFC 2104][rfc2104]
HS384 | HMAC using SHA-384
HS512 | HMAC using SHA-512
RS256 | RSASSA-PKCS-v1_5 using SHA-256 per [RFC3447][rfc3447]
RS384 | RSASSA-PKCS-v1_5 using SHA-384
RS512 | RSASSA-PKCS-v1_5 using SHA-512
ES256 | ECDSA using P-256 and SHA-256 per [DSS][dss]
ES384 | ECDSA using P-384 and SHA-384
ES512 | ECDSA using P-521 and SHA-512
none | No digital signature or MAC performed (unsecured)

### Supported Ruby Versions
Ruby 2.2 and up

### Limitations
Future implementation may include these features:

- processing of OPTIONAL JWT registered claim names (e.g. 'exp')
- representation of a JWT as a JSON Web Encryption (JWE) [RFC 7516][rfc7516]
- OPTIONAL nested JWTs

[rfc2104]: http://tools.ietf.org/html/rfc2104
[rfc3447]: http://tools.ietf.org/html/rfc3447
[rfc7515]: http://tools.ietf.org/html/rfc7515
[rfc7516]: http://tools.ietf.org/html/rfc7516
[rfc7518]: http://tools.ietf.org/html/rfc7518
[rfc7519]: http://tools.ietf.org/html/rfc7519
[dss]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

[thomson-postel]: https://tools.ietf.org/html/draft-thomson-postel-was-wrong-00
[cors]: http://www.w3.org/TR/cors/
[devise]: https://github.com/plataformatec/devise
[doorkeeper]: https://github.com/doorkeeper-gem/doorkeeper
[oauth2]: https://github.com/intridea/oauth2
[rack-cors]: https://github.com/cyu/rack-cors

[travis]: https://travis-ci.org/garyf/json_web_token
[ci_img]: https://travis-ci.org/garyf/json_web_token.svg?branch=master
[yard_docs]: http://www.rubydoc.info/github/garyf/json_web_token
[yd_img]: http://img.shields.io/badge/yard-docs-blue.svg
[code_climate]: https://codeclimate.com/github/garyf/json_web_token
[cc_img]: https://codeclimate.com/github/garyf/json_web_token/badges/gpa.svg
