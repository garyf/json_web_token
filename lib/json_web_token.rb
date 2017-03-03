require 'json_web_token/jwt'

# Top level interface, or API, to sign and verify a JSON Web Token (JWT)
# @see http://tools.ietf.org/html/rfc7519
module JsonWebToken

  module_function

  # @param claims [Hash] a collection of name/value pairs asserting information about a subject
  # @param options [Hash] specify the desired signing algorithm and signing key
  # @return [String] a JSON Web Token, representing digitally signed claims
  # @example
  #   claims = {iss: 'joe', exp: 1300819380, :'http://example.com/is_root' => true}
  #   options = {alg: 'HS256', key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'}
  #   JsonWebToken.sign(claims, options)
  #   # => 'eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4'
  def sign(claims, options)
    Jwt.sign(claims, options)
  end

  # @param jwt [String] a JSON Web Token
  # @param options [Hash] specify the desired verifying algorithm and verifying key
  # @return [Hash] +{ok: < the jwt claims set hash >}+ if the jwt verifies,
  #   or +{error: 'Invalid'}+ otherwise
  # @example
  #   jwt = 'eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4'
  #   options = {alg: 'HS256', key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'}
  #   JsonWebToken.verify(jwt, options)
  #   # => {ok: {iss: 'joe', exp: 1300819380, :'http://example.com/is_root' => true}}
  def verify(jwt, options)
    Jwt.verify(jwt, options)
  end
end

# alias
JWT = JsonWebToken unless ENV['RUBY_GEM_JSON_WEB_TOKEN_SKIP_ALIAS']
