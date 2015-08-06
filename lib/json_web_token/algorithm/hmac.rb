require 'json_web_token/algorithm/common'
require 'json_web_token/util'

module JsonWebToken
  module Algorithm
    # Sign or verify a JSON Web Signature (JWS) structure using HMAC with SHA-2 algorithms
    # @see http://tools.ietf.org/html/rfc7518#section-3.2
    module Hmac

      extend JsonWebToken::Algorithm::Common

      module_function

      # @param sha_bits [String] size of the hash output
      # @param shared_key [String] secret key used to sign and verify a digital signature, or mac
      # @param signing_input [String] input payload for a mac computation
      # @return [BinaryString] a digital signature, or mac
      # @example
      #   shared_key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      #   Hmac.sign('256', shared_key, 'signing_input').bytes
      #   # => [90, 34, 44, 252, 147, 130, 167, 173, 86, 191, 247, 93, 94, 12, 200, 30, 173, 115, 248, 89, 246, 222, 4, 213, 119, 74, 70, 20, 231, 194, 104, 103]
      def sign(sha_bits, shared_key, signing_input)
        validate_key(sha_bits, shared_key)
        OpenSSL::HMAC.digest(digest_new(sha_bits), shared_key, signing_input)
      end

      # @param mac [BinaryString] a digital signature, or mac
      # @param (see #sign)
      # @return [Boolean] a predicate to verify the signing_input by comparing a given +mac+
      #   to the +mac+ for a newly signed message; comparison done in a constant-time manner
      #   to thwart timing attacks
      # @example
      #   shared_key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      #   Hmac.verify?(< binary_string >, '256', shared_key, 'signing_input')
      #   # => true
      def verify?(mac, sha_bits, shared_key, signing_input)
        Util.constant_time_compare?(mac, sign(sha_bits, shared_key, signing_input))
      end

      def validate_key_size(sha_bits, key)
        fail('Invalid shared key') if weak_key?(sha_bits, key)
      end

      def weak_key?(sha_bits, key)
        !key || key.bytesize * 8 < sha_bits.to_i
      end

      private_class_method :validate_key_size,
        :weak_key?
    end
  end
end
