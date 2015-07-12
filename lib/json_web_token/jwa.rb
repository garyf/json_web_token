require 'json_web_token/algorithm/ecdsa'
require 'json_web_token/algorithm/hmac'
require 'json_web_token/algorithm/rsa'

module JsonWebToken
  module Jwa

    ALGORITHMS = /(HS|RS|ES)(256|384|512)?/i
    ALG_LENGTH = 5

    module_function

    def signed(algorithm, key, data)
      alg = validated_alg(algorithm)
      alg[:constant].signed(alg[:sha_bits], key, data)
    end

    def verified?(signature, algorithm, key, data)
      alg = validated_alg(algorithm)
      alg[:constant].verified?(signature, alg[:sha_bits], key, data)
    end

    # private

    def validated_alg(algorithm)
      alg = destructured_alg(algorithm)
      alg ? alg : fail('Unrecognized algorithm')
    end

    def destructured_alg(algorithm)
      match = algorithm.match(ALGORITHMS)
      return unless match && match[0].length == ALG_LENGTH
      {
        constant: validated_constant(match[1].downcase),
        sha_bits: match[2],
      }
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
      :destructured_alg
      :validated_constant
  end
end
