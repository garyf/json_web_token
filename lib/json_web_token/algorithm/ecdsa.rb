require 'json_web_token/algorithm/common'
require 'json_web_token/format/asn1'

module JsonWebToken
  module Algorithm
    # Sign or verify a JSON Web Signature (JWS) structure using ECDSA
    # @see http://tools.ietf.org/html/rfc7518#section-3.4
    module Ecdsa

      extend JsonWebToken::Algorithm::Common
      extend JsonWebToken::Format::Asn1

      MAC_BYTE_COUNT = {
        '256' => 64, # prime256v1 aka: secp256r1
        '384' => 96, # secp384r1
        '512' => 132 # secp521r1 note difference (not 128) due to using 521-bit integers
      }

      module_function

      # @param sha_bits [String] desired security level in bits of the signature scheme
      # @param private_key [OpenSSL::PKey::EC] key used to sign a digital signature, or mac
      # @param signing_input [String] input payload for a mac computation
      # @return [BinaryString] a digital signature, or mac
      # @example
      #   Ecdsa.sign('256', private_key, 'signing_input').bytes
      #   # => [90, 34, 44, 252, 147, 130, 167, 173, 86, 191, 247, 93, 94, 12, 200, 30, 173, 115, 248, 89, 246, 222, 4, 213, 119, 74, 70, 20, 231, 194, 104, 103]
      def sign(sha_bits, private_key, signing_input)
        validate_key(sha_bits, private_key)
        der = private_key.dsa_sign_asn1(ssl_digest_hash sha_bits, signing_input)
        der_to_signature(der, sha_bits)
      end

      # @param mac [BinaryString] a digital signature, or mac
      # @param sha_bits [String] desired security level in bits of the signature scheme
      # @param public_key [OpenSSL::PKey::EC] key used to verify a digital signature, or mac
      # @param signing_input [String] input payload for a mac computation
      # @return [Boolean] a predicate to verify the signing_input for a given +mac+
      # @example
      #   Ecdsa.verify?(< binary_string >, '256', < public_key >, 'signing_input')
      #   # => true
      def verify?(mac, sha_bits, public_key, signing_input)
        validate_key(sha_bits, public_key)
        validate_signature_size(mac, sha_bits)
        der = signature_to_der(mac, sha_bits)
        public_key.dsa_verify_asn1(ssl_digest_hash(sha_bits, signing_input), der)
      end

      def validate_key_size(_sha_bits, _key); end

      def ssl_digest_hash(sha_bits, signing_input)
        digest_new(sha_bits).digest(signing_input)
      end

      def validate_signature_size(mac, sha_bits)
        fail('Invalid signature') unless mac && mac.bytesize == MAC_BYTE_COUNT[sha_bits]
      end

      private_class_method :validate_key_size,
        :ssl_digest_hash,
        :validate_signature_size
    end
  end
end
