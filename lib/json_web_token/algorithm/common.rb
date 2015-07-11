require 'openssl'

module JsonWebToken
  module Algorithm
    module Common

      SHA_BITS = [
        '256',
        '384',
        '512'
      ]

      def validate_key(key, sha_bits)
        validate_sha_bits(sha_bits)
        validate_key_size(key, sha_bits)
      end

      def validate_sha_bits(sha_bits)
        fail('Invalid sha_bits') unless SHA_BITS.include?(sha_bits)
      end

      def digest_new(sha_bits)
        OpenSSL::Digest.new("sha#{sha_bits}")
      end
    end
  end
end
