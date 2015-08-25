require 'json'
require 'json_web_token/format/base64_url'
require 'json_web_token/jwa'
require 'json_web_token/util'

module JsonWebToken
  # Represent content to be secured with digital signatures or Message Authentication Codes (MACs)
  # @see http://tools.ietf.org/html/rfc7515
  module Jws

    MESSAGE_SIGNATURE_PARTS = 3

    module_function

    # @param header [Hash] the desired set of JWS header parameters
    # @param payload [String] content to be used as the JWS payload
    # @param key [String | OpenSSL::PKey::RSA | OpenSSL::PKey::EC] secret key used to sign
    #   a digital signature, or mac
    # @return [String] a JSON Web Signature, representing a digitally signed payload
    # @example
    #   header = {alg: 'HS256'}
    #   key = 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'
    #   Jws.sign(header, 'payload', key)
    #   # => 'eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4'
    # @see http://tools.ietf.org/html/rfc7515#page-15
    def sign(header, payload, key)
      alg = alg_parameter(header)
      signing_input = encode_input(header, payload)
      "#{signing_input}.#{signature(alg, key, signing_input)}"
    end

    # @param header [Hash] the desired set of JWS header parameters
    # @param payload [String] content to be used as the JWS payload
    # @return [String] a JWS that provides no integrity protection (i.e. lacks a signature)
    # @example
    #   header = {alg: 'none'}
    #   Jws.sign(header, 'payload')
    #   # => 'eyJhbGciOiJub25lIn0.cGF5bG9hZA.'
    # @see http://tools.ietf.org/html/rfc7515#page-47
    def unsecured_message(header, payload)
      fail("Invalid 'alg' header parameter") unless alg_parameter(header) == 'none'
      "#{encode_input(header, payload)}." # note trailing '.'
    end

    # @param jws [String] a JSON Web Signature
    # @param algorithm [String] 'alg' header parameter value for JWS
    # @param key [String | OpenSSL::PKey::RSA | OpenSSL::PKey::EC] key used to verify
    #   a digital signature, or mac
    # @return [Hash] +{ok: <the jws string>}+ if the mac verifies,
    #   or +{error: 'invalid'}+ otherwise
    # @example
    #   jws = 'eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4'
    #   key = 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'
    #   Jws.verify(jws, 'HS256', key)
    #   # => {ok: 'eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4'}
    # @see http://tools.ietf.org/html/rfc7515#page-16
    def verify(jws, algorithm, key = nil)
      validate_alg_match(jws, algorithm)
      return {ok: jws} if algorithm == 'none'
      signature_verify?(jws, algorithm, key) ? {ok: jws} : {error: 'invalid'}
    end

    def alg_parameter(header)
      alg = Util.symbolize_keys(header)[:alg]
      alg && !alg.empty? ? alg : fail("Missing required 'alg' header parameter")
    end

    def encode_input(header, payload)
      "#{Format::Base64Url.encode(header.to_json)}.#{Format::Base64Url.encode(payload)}"
    end

    def signature(algorithm, key, data)
      Format::Base64Url.encode(Jwa.sign(algorithm, key, data))
    end

    # http://tools.ietf.org/html/rfc7515#section-4.1.1
    def validate_alg_match(jws, algorithm)
      header = decoded_header_json_to_hash(jws)
      unless alg_parameter(header) == algorithm
        fail("Algorithm not matching 'alg' header parameter")
      end
    end

    def decoded_header_json_to_hash(jws)
      JSON.parse(Format::Base64Url.decode(jws.split('.')[0]))
    end

    def signature_verify?(jws, algorithm, key)
      ary = jws.split('.')
      return unless key && ary.length == MESSAGE_SIGNATURE_PARTS
      decoded_signature = Format::Base64Url.decode(ary[2])
      payload = "#{ary[0]}.#{ary[1]}"
      Jwa.verify?(decoded_signature, algorithm, key, payload)
    end

    private_class_method :alg_parameter,
      :encode_input,
      :signature,
      :validate_alg_match,
      :decoded_header_json_to_hash,
      :signature_verify?
  end
end
