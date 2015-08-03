require 'openssl'

module JsonWebToken
  module Algorithm
    module Common

      SHA_BITS = [
        '256',
        '384',
        '512'
      ]

      def validate_key(sha_bits, key)
        validate_sha_bits(sha_bits)
        validate_key_size(sha_bits, key)
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
