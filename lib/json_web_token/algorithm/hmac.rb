require 'openssl'

module JsonWebToken
  module Algorithm
    module Hmac

      module_function

      def signed(sha_bits, key, data)
        OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha#{sha_bits}"), key, data)
      end

      def verified?(signature, sha_bits, key, data)
        signature == signed(sha_bits, key, data)
      end
    end
  end
end
