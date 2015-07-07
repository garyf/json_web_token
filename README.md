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
Create a JSON web token

```ruby
require 'json_web_token'

JsonWebToken.create(claims, options)
```

Validate a JSON web token

```ruby
JsonWebToken.validate(jwt, options)
```
### Supported encryption algorithms
The 2 REQUIRED JWT algorithms

- HMAC using SHA-256 per [RFC 2104][rfc2104]
- none (unsecured)

### Supported Ruby Versions
Ruby 2.1 and up

### Limitations
Future implementation may include these features:

- Representation of a JWT as a JSON Web Encryption (JWE) [RFC 7516][rfc7516]
- RECOMMENDED or OPTIONAL encryption algorithms
- OPTIONAL nested JWTs

[rfc2104]: http://tools.ietf.org/html/rfc2104
[rfc7515]: http://tools.ietf.org/html/rfc7515
[rfc7516]: http://tools.ietf.org/html/rfc7516
[rfc7518]: http://tools.ietf.org/html/rfc7518
[rfc7519]: http://tools.ietf.org/html/rfc7519

[cors]: http://www.w3.org/TR/cors/
[devise]: https://github.com/plataformatec/devise
[doorkeeper]: https://github.com/doorkeeper-gem/doorkeeper
[oauth2]: https://github.com/intridea/oauth2
[rack-cors]: https://github.com/cyu/rack-cors
