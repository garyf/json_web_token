require 'json_web_token/algorithm/ecdsa'
require 'json_web_token/algorithm/hmac'
require 'json_web_token/algorithm/rsa'

module JsonWebToken
  # Choose a cryptographic algorithm to be used for a JSON Web Signature (JWS)
  # @see http://tools.ietf.org/html/rfc7518
  module Jwa

    ALGORITHMS = /(HS|RS|ES)(256|384|512)?/i
    ALG_LENGTH = 5

    module_function

    # @param algorithm [String] 'alg' header parameter value for JWS
    # @param key [String | OpenSSL::PKey::RSA | OpenSSL::PKey::EC] secret key used to sign
    #   a digital signature, or mac
    # @param signing_input [String] input payload for a mac computation
    # @return [BinaryString] a digital signature, or mac
    # @example
    #   key = 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'
    #   Jwa.sign('HS256', key, 'signing_input').bytes
    #   # => [90, 34, 44, 252, 147, 130, 167, 173, 86, 191, 247, 93, 94, 12, 200, 30, 173, 115, 248, 89, 246, 222, 4, 213, 119, 74, 70, 20, 231, 194, 104, 103]
    def sign(algorithm, key, signing_input)
      alg_module, sha_bits = validated_alg(algorithm)
      alg_module.sign(sha_bits, key, signing_input)
    end

    # @param mac [BinaryString] a digital signature, or mac
    # @param algorithm [String] 'alg' header parameter value for JWS
    # @param key [String | OpenSSL::PKey::RSA | OpenSSL::PKey::EC] key used to verify
    #   a digital signature, or mac
    # @param signing_input [String] input payload for a mac computation
    # @example
    #   key = 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'
    #   Jwa.verify?(< binary_string >, 'HS256', key, 'signing_input')
    #   # => true
    def verify?(mac, algorithm, key, signing_input)
      alg_module, sha_bits = validated_alg(algorithm)
      alg_module.verify?(mac, sha_bits, key, signing_input)
    end

    def validated_alg(algorithm)
      alg = destructured_alg(algorithm)
      alg ? alg : fail('Unrecognized algorithm')
    end

    def destructured_alg(algorithm)
      match = algorithm.match(ALGORITHMS)
      return unless match && match[0].length == ALG_LENGTH
      alg_module = validated_constant(match[1].downcase)
      sha_bits = match[2]
      [alg_module, sha_bits]
    end

    def validated_constant(str)
      case str
      when 'hs' then Algorithm::Hmac
      when 'rs' then Algorithm::Rsa
      when 'es' then Algorithm::Ecdsa
      else fail('Unsupported algorithm')
      end
    end

    private_class_method :validated_alg,
      :destructured_alg,
      :validated_constant
  end
end
