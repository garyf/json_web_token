require 'base64'

module JsonWebToken
  module Format
    module Base64Url

      module_function

      def encode(str)
        url_safe_encode(str)
      end

      def decode(str)
        url_safe_decode(str)
      end

      # private

      # http://tools.ietf.org/html/rfc7515#appendix-C
      def url_safe_encode(str)
        remove_base64_padding(Base64.urlsafe_encode64 str)
      end

      def url_safe_decode(str)
        Base64.urlsafe_decode64(add_base64_padding str)
      end

      def remove_base64_padding(encoded)
        encoded.gsub(/[=]/, '')
      end

      def add_base64_padding(str)
        mod = str.length % 4
        return str if mod == 0
        fail('Invalid base64 string') if mod == 1
        "#{str}#{'=' * (4 - mod)}"
      end

      private_class_method :url_safe_encode,
        :url_safe_decode,
        :remove_base64_padding,
        :add_base64_padding
    end
  end
end
