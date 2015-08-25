## Changelog

### v0.3.1 (2015-08-25)

* bug fix
  * README escaping removed

### v0.3.0 (2015-08-25)

* backward incompatible changes
  * JsonWebToken, Jwt, and Jws #verify return values

### v0.2.2 (2015-08-06)

* enhancements
  * RsaUtil to read keys from pem files

### v0.2.1 (2015-08-03)

* enhancements
  * Rsa#validate\_message\_size

### v0.2.0 (2015-08-02)

* backward incompatible changes
  * Top level API now #sign and #verify

### v0.1.2 (2015-08-02)

* enhancements
  * Jws#verify returns false (rather than 'Invalid') unless the signature is verified

### v0.1.1 (2015-07-13)

* bug fix
  * #symbolize_keys spec failing on < ruby-2.2.0

### v0.1.0 (2015-07-12)

* enhancements
  * support ECDSA algorithm

### v0.0.2 (2015-07-11)

* enhancements
  * support RSASSA-PKCS-v1_5 algorithm

### v0.0.1 (2015-07-09)

* initial
  * support HMAC algorithm
