require 'openssl'

module JsonWebToken
  module Algorithm
    module Hmac

      SHA_BITS = [
        '256',
        '384',
        '512'
      ]

      module_function

      def signed(sha_bits, key, data)
        validate_params(key, sha_bits)
        OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha#{sha_bits}"), key, data)
      end

      def verified?(mac, sha_bits, key, data)
        validate_params(key, sha_bits)
        mac == signed(sha_bits, key, data)
      end

      # private

      def validate_params(key, sha_bits)
        validate_sha_bits(sha_bits)
        validate_key_size(key, sha_bits)
      end

      def validate_sha_bits(sha_bits)
        fail('Invalid sha_bits') unless SHA_BITS.include?(sha_bits)
      end

      # http://tools.ietf.org/html/rfc7518#section-3.2
      def validate_key_size(key, sha_bits)
        fail('Invalid key') unless key && key.bytesize * 8 >= sha_bits.to_i
      end

      private_class_method :validate_params,
        :validate_sha_bits,
        :validate_key_size
    end
  end
end
