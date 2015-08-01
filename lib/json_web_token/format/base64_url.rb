require 'base64'

module JsonWebToken
  module Format
    # Provide base64url encoding and decoding functions without padding, based upon standard
    # base64 encoding and decoding functions that do use padding
    # @see http://tools.ietf.org/html/rfc7515#appendix-C
    module Base64Url
      module_function

      # @param str [String]
      # @return [String] a urlsafe_encode64 string with all trailing '=' padding removed
      # @example
      #   Base64Url.encode('foo')
      #   # => 'Zm9v'
      def encode(str)
        base64_padding_removed(Base64.urlsafe_encode64(str))
      end

      # @param str [String] encoded as url_encode64
      # @return [String] with trailing '=' padding added before decoding
      # @example
      #   Base64Url.decode("YmFy")
      #   # => 'bar'
      def decode(str)
        Base64.urlsafe_decode64(base64_padding_added(str))
      end

      def base64_padding_removed(encoded)
        encoded.gsub(/[=]/, '')
      end

      def base64_padding_added(str)
        mod = str.length % 4
        return str if mod == 0
        fail('Invalid base64 string') if mod == 1
        "#{str}#{'=' * (4 - mod)}"
      end

      private_class_method :base64_padding_removed,
        :base64_padding_added
    end
  end
end
