require 'json_web_token/jws'

module JsonWebToken
  # Encode claims for transmission as a JSON object that is used as the payload of a JSON Web
  # Signature (JWS) structure, enabling the claims to be integrity protected with a Message
  # Authentication Code (MAC), to be later verified
  # @see http://tools.ietf.org/html/rfc7519
  module Jwt

    ALG_DEFAULT = 'HS256'
    HEADER_DEFAULT = {
      typ: 'JWT',
      alg: ALG_DEFAULT
    }

    module_function

    # @param claims [Hash] a collection of name/value pairs asserting information about a subject
    # @param options [Hash] specify the desired signing algorithm and signing key
    #   (e.g String for Hmac | OpenSSL::PKey::RSA | OpenSSL::PKey::EC)
    # @return [String] a JSON Web Token, representing digitally signed claims
    # @example
    #   claims = {iss: 'joe', exp: 1300819380, :'http://example.com/is_root' => true}
    #   options = {alg: 'HS256', key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'}
    #   Jwt.sign(claims, options)
    #   # => 'eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4'
    # @see http://tools.ietf.org/html/rfc7519#section-7.1
    def sign(claims, options)
      message = validated_message(claims)
      header = config_header(options)
      return Jws.unsecured_message(header, message) if header[:alg] == 'none'
      Jws.sign(header, message, options[:key])
    end

    # @param jwt [String] a JSON Web Token
    # @param options [Hash] specify the desired verifying algorithm and verifying key
    # @return [Hash] +{ok: <the jwt claims set hash>}+ if the jwt verifies,
    #   or +{error: 'Invalid'}+ otherwise
    # @example
    #   jwt = 'eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4'
    #   options = {alg: 'HS256', key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'}
    #   Jwt.verify(jwt, options)
    #   # => {ok: {iss: 'joe', exp: 1300819380, :'http://example.com/is_root' => true}}
    # @see see http://tools.ietf.org/html/rfc7519#section-7.2
    def verify(jwt, options)
      alg = options[:alg] || ALG_DEFAULT
      payload(Jws.verify(jwt, alg, options[:key]))
    end

    def validated_message(claims)
      fail('Claims blank') if !claims || claims.empty?
      claims.to_json
    end

    def config_header(options)
      HEADER_DEFAULT.merge(alg_parameter_required options)
    end

    def alg_parameter_required(options)
      hsh = options.select { |k, _v| k == :alg } # filter unsupported keys
      alg = hsh[:alg]
      alg && !alg.empty? ? hsh : {}
    end

    def payload(hsh)
      return {error: 'invalid'} if hsh[:error]
      ary = hsh[:ok].split('.')
      return {error: 'invalid JWS'} unless ary.length > 1
      encoded_claims = ary[1]
      {ok: payload_to_hash(encoded_claims)}
    end

    def payload_to_hash(encoded_claims)
      Util.symbolize_keys(JSON.parse(Format::Base64Url.decode encoded_claims))
    end

    private_class_method :validated_message,
      :config_header,
      :alg_parameter_required,
      :payload,
      :payload_to_hash
  end
end
