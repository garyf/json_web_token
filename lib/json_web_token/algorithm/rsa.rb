require 'json_web_token/algorithm/common'

module JsonWebToken
  module Algorithm
    module Rsa

      extend JsonWebToken::Algorithm::Common

      KEY_BITS_MIN = 2048

      module_function

      def signed(sha_bits, key, data)
        validate_key(key, sha_bits)
        key.sign(digest_new(sha_bits), data)
      end

      def verified?(signature, sha_bits, key, data)
        validate_key(key, sha_bits)
        key.verify(digest_new(sha_bits), signature, data)
      end

      # private

      # http://tools.ietf.org/html/rfc7518#section-3.3
      # https://github.com/ruby/openssl/issues/5
      def validate_key_size(key, sha_bits)
        fail('Invalid private key') unless key && key.n.num_bits >= KEY_BITS_MIN
      end

      private_class_method :validate_key_size
    end
  end
end
