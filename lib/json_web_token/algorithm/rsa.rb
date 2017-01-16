require 'json_web_token/algorithm/common'

module JsonWebToken
  module Algorithm
    # Sign or verify a JSON Web Signature (JWS) structure using RSASSA-PKCS-v1_5
    # @see http://tools.ietf.org/html/rfc7518#section-3.3
    module Rsa
      extend JsonWebToken::Algorithm::Common

      KEY_BITS_MIN = 2048

      module_function

      # @param sha_bits [String] desired security level in bits of the signature scheme
      # @param private_key [OpenSSL::PKey::RSA] key used to sign a digital signature, or mac
      # @param signing_input [String] input payload for a mac computation
      # @return [BinaryString] a digital signature, or mac
      # @example
      #   Rsa.sign('256', < private_key >, 'signing_input').bytes.length
      #   # => 256
      def sign(sha_bits, private_key, signing_input)
        validate_key(sha_bits, private_key)
        private_key.sign(digest_new(sha_bits), signing_input)
      end

      # @param mac [BinaryString] a digital signature, or mac
      # @param sha_bits [String] desired security level in bits of the signature scheme
      # @param public_key [OpenSSL::PKey::RSA] key used to verify a digital signature, or mac
      # @param signing_input [String] input payload for a mac computation
      # @return [Boolean] a predicate to verify the signing_input for a given +mac+
      # @example
      #   Rsa.verify?(< binary_string >, '256', < public_key >, 'signing_input')
      #   # => true
      def verify?(mac, sha_bits, public_key, signing_input)
        validate_key(sha_bits, public_key)
        public_key.verify(digest_new(sha_bits), mac, signing_input)
      end

      def validate_key_size(_sha_bits, key)
        fail('Invalid key: RSA modulus too small') if weak_key?(key)
      end

      # https://github.com/ruby/openssl/issues/5
      def weak_key?(key)
        !key || key.n.num_bits < KEY_BITS_MIN
      end

      private_class_method :validate_key_size,
        :weak_key?
    end
  end
end
