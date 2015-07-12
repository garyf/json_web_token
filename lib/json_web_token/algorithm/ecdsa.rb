require 'json_web_token/algorithm/common'
require 'json_web_token/format/asn1'

module JsonWebToken
  module Algorithm
    module Ecdsa

      extend JsonWebToken::Algorithm::Common
      extend JsonWebToken::Format::Asn1

      MAC_BYTE_COUNT = {
        '256' => 64, # secp256k1
        '384' => 96, # secp384r1
        '512' => 132 # secp521r1 note difference (not 128) due to using 521-bit integers
      }

      module_function

      def signed(sha_bits, private_key, data)
        validate_key(private_key, sha_bits)
        der = private_key.dsa_sign_asn1(ssl_digest_hash sha_bits, data)
        der_to_signature(der, sha_bits)
      end

      def verified?(signature, sha_bits, key, data)
        validate_key(key, sha_bits)
        validate_signature_size(signature, sha_bits)
        der = signature_to_der(signature, sha_bits)
        key.dsa_verify_asn1(ssl_digest_hash(sha_bits, data), der)
      end

      # private

      def validate_key_size(_key, _sha_bits); end

      def ssl_digest_hash(sha_bits, data)
        digest_new(sha_bits).digest(data)
      end

      def validate_signature_size(signature, sha_bits)
        n = MAC_BYTE_COUNT[sha_bits]
        fail('Invalid signature') unless signature && signature.bytesize == n
      end

      private_class_method :validate_key_size,
        :ssl_digest_hash,
        :validate_signature_size
    end
  end
end
