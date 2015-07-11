# JSON Web Token

## A JSON Web Token implementation for Ruby
**Work in progress -- not yet ready for production**

### Description
A Ruby implementation of the JSON Web Token (JWT) Standards Track [RFC 7519][rfc7519]

## Installation
    gem install json_web_token

### Philosophy & Design Goals
* Minimal API surface area
* Clear separation and conformance to underlying standards
  - JSON Web Signature (JWS) Standards Track [RFC 7515][rfc7515]
  - JSON Web Algorithms (JWA) Standards Track [RFC 7518][rfc7518]
* Thorough test coverage
* Modularity for comprehension and extensibility
* Implement only the REQUIRED elements of the JWT standard (initially)

### Intended Audience
Token authentication of API requests to Rails via these popular gems

- [Devise][devise]
- [Doorkeeper][doorkeeper]
- [OAuth2][oauth2]

Secure Cross-Origin Resource Sharing ([CORS][cors]) using the [rack-cors][rack-cors] gem

## Usage

### JsonWebToken.create(claims, options)

Returns a JSON Web Token string

`claims` (required) string or hash

`options` (optional) hash

* **alg**, default: `HS256`
* **key** (required unless alg is 'none')

Example

```ruby
require 'json_web_token'

# sign with default algorithm, HMAC SHA256
jwt = JsonWebToken.create({foo: 'bar'}, key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C')

# sign with RSA SHA256 algorithm
options = {
  alg: 'RSA256',
  key: < RSA private key >
}

jwt = JsonWebToken.create({foo: 'bar'}, options)

# unsecured token (algorithm is 'none')
jwt = JsonWebToken.create({foo: 'bar'}, alg: 'none')

```

### JsonWebToken.validate(jwt, options)

Returns a JWT claims set string or hash, if the MAC signature is valid

`jwt` (required) is a JSON web token string

`options` (optional) hash

* **algorithm**, default: `HS256`
* **key** (required unless alg is 'none')

Example

```ruby
require 'json_web_token'

secure_jwt = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt.cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

# verify with default algorithm, HMAC SHA256
claims = JsonWebToken.validate(secure_jwt, key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C')

# verify with RSA SHA256 algorithm
options = {
  alg: 'RSA256',
  key: < RSA public key >
}

claims = JsonWebToken.validate(jwt, options)

# unsecured token (algorithm is 'none')

unsecured_jwt = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt.'

claims = JsonWebToken.validate(unsecured_jwt, alg: 'none')

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
none | No digital signature or MAC performed (unsecured)

### Supported Ruby Versions
Ruby 2.0 and up

### Limitations
Future implementation may include these features:

- additional RECOMMENDED or OPTIONAL encryption algorithms
- representation of a JWT as a JSON Web Encryption (JWE) [RFC 7516][rfc7516]
- OPTIONAL nested JWTs

[rfc2104]: http://tools.ietf.org/html/rfc2104
[rfc3447]: http://tools.ietf.org/html/rfc3447
[rfc7515]: http://tools.ietf.org/html/rfc7515
[rfc7516]: http://tools.ietf.org/html/rfc7516
[rfc7518]: http://tools.ietf.org/html/rfc7518
[rfc7519]: http://tools.ietf.org/html/rfc7519

[cors]: http://www.w3.org/TR/cors/
[devise]: https://github.com/plataformatec/devise
[doorkeeper]: https://github.com/doorkeeper-gem/doorkeeper
[oauth2]: https://github.com/intridea/oauth2
[rack-cors]: https://github.com/cyu/rack-cors
