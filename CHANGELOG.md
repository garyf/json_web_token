## Changelog

### v0.3.5 (2017-06-17)

* Bug fixes
  * Replace ECDSA curve secp256k1 in spec with prime256v1 (aka secp256r1)

* Enhancements
  * Remove travis CI for ruby < v2.2
  * Update gem dependency versions

### v0.3.4 (2017-03-02)

* Enhancements
  * Alias `JWT` for `JsonWebToken` can be turned off with `RUBY_GEM_JSON_WEB_TOKEN_SKIP_ALIAS` environment variable

### v0.3.3 (2017-01-16)

* Bug fixes
  * Remove invalid RSA .validate_message_size

### v0.3.2 (2016-10-09)

* Enhancements
  * Modernized the dev environment
  * Added a `Support for JWT Registered Claims` section to the README, along with a link to the companion `jwt_claims` gem
  * Fixed the README examples by using working tokens

### v0.3.1 (2015-08-25)

* Bug fixes
  * README escaping removed

### v0.3.0 (2015-08-25)

* Backward incompatible changes
  * JsonWebToken, Jwt, and Jws #verify return values

### v0.2.2 (2015-08-06)

* Enhancements
  * RsaUtil to read keys from pem files

### v0.2.1 (2015-08-03)

* Enhancements
  * Rsa#validate\_message\_size

### v0.2.0 (2015-08-02)

* Backward incompatible changes
  * Top level API now #sign and #verify

### v0.1.2 (2015-08-02)

* Enhancements
  * Jws#verify returns false (rather than 'Invalid') unless the signature is verified

### v0.1.1 (2015-07-13)

* Bug fixes
  * #symbolize_keys spec failing on < ruby-2.2.0

### v0.1.0 (2015-07-12)

* Enhancements
  * support ECDSA algorithm

### v0.0.2 (2015-07-11)

* Enhancements
  * support RSASSA-PKCS-v1_5 algorithm

### v0.0.1 (2015-07-09)

* Initial
  * support HMAC algorithm
