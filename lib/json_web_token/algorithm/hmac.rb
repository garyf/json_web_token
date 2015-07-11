require 'json_web_token/algorithm/common'
require 'json_web_token/util'

module JsonWebToken
  module Algorithm
    module Hmac

      extend JsonWebToken::Algorithm::Common

      module_function

      def signed(sha_bits, key, data)
        validate_key(key, sha_bits)
        OpenSSL::HMAC.digest(digest_new(sha_bits), key, data)
      end

      def verified?(mac, sha_bits, key, data)
        validate_key(key, sha_bits)
        Util.constant_time_compare(mac, signed(sha_bits, key, data))
      end

      # private

      # http://tools.ietf.org/html/rfc7518#section-3.2
      def validate_key_size(key, sha_bits)
        fail('Invalid key') unless key && key.bytesize * 8 >= sha_bits.to_i
      end

      private_class_method :validate_key_size
    end
  end
end
