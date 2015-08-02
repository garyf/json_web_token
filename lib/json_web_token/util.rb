module JsonWebToken
  # Utility methods
  module Util

    module_function

    # @param a [String]
    # @param b [String]
    # @return [Boolean] a predicate that compares two strings for equality in constant-time
    #   to avoid timing attacks
    # @example
    #   Util.constant_time_compare?("a", "A")
    #   # => false
    # @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.2
    # @see cf. rails activesupport/lib/active_support/security_utils.rb
    def constant_time_compare?(a, b)
      return false if a.nil? || b.nil? || a.empty? || b.empty?
      secure_compare(a, b)
    end

    # @param hsh [Hash]
    # @return [Hash] a new hash with all keys converted to symbols,
    #   as long as they respond to to_sym
    # @example
    #   Util.symbolize_keys({'a' =>  0, 'b' => '2', c: '3'})
    #   # => {a: 0, b: '2', c: '3'}
    # @see cf. rails activesupport/lib/active_support/core_ext/hash/keys.rb
    def symbolize_keys(hsh)
      transform_keys(hsh) { |key| key.to_sym rescue key }
    end

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
