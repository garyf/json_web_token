module JsonWebToken
  module Util

    module_function

    # https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.2
    def constant_time_compare?(a, b)
      return false if a.nil? || b.nil? || a.empty? || b.empty?
      secure_compare(a, b)
    end

    # cf. rails activesupport/lib/active_support/core_ext/hash/keys.rb
    def symbolize_keys(hsh)
      transform_keys(hsh) { |key| key.to_sym rescue key }
    end

    # private

    # cf. rails activesupport/lib/active_support/security_utils.rb
    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize
      l = a.unpack "C#{a.bytesize}"
      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res == 0
    end

    def transform_keys(hsh)
      result = Hash.new
      hsh.keys.each { |k| result[yield(k)] = hsh[k] }
      result
    end

    private_class_method :secure_compare,
      :transform_keys
  end
end
