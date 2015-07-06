require 'json_web_token/algorithm/hmac'

module JsonWebToken
  module Jwa

    ALGORITHMS = /(HS)(256|384|512)?/i
    ALG_LENGTH = 5

    module_function

    def signed(algorithm, key, data)
      alg = validated_alg(algorithm)
      sha_bits = alg[:sha_bits]
      case alg[:kind]
      when 'hs'
        Algorithm::Hmac.signed(sha_bits, key, data)
      else
        fail('Unsupported algorithm')
      end
    end

    def verified?(signature, algorithm, key, data)
      alg = validated_alg(algorithm)
      sha_bits = alg[:sha_bits]
      case alg[:kind]
      when 'hs'
        Algorithm::Hmac.verified?(signature, sha_bits, key, data)
      else
        false
      end
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
        kind: match[1].downcase,
        sha_bits: match[2]
      }
    end

    private_class_method :validated_alg,
      :destructured_alg
  end
end
