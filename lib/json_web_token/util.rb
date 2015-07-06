module JsonWebToken
  module Util

    module_function

    # cf. rails activesupport/lib/active_support/core_ext/hash/keys.rb
    def symbolize_keys(hsh)
      transform_keys(hsh) { |key| key.to_sym rescue key }
    end

    # private

    def transform_keys(hsh)
      result = Hash.new
      hsh.keys.each { |k| result[yield(k)] = hsh[k] }
      result
    end

    private_class_method :transform_keys
  end
end
