require 'openssl'

module JsonWebToken
  module Format
    # ASN1 data structures are usually encoded using the Distinguished Encoding Rules (DER).
    # The ASN1 module provides the necessary classes that allow generation of ASN1 data
    # structures and the methods to encode them using a DER encoding. The decode method allows
    # parsing arbitrary DER-encoded data to a Ruby object that can then be modified and
    # re-encoded at will.
    # @see http://docs.ruby-lang.org/en/2.1.0/OpenSSL/ASN1.html
    module Asn1

      KEY_BITS = {
        '256' => 256,
        '384' => 384,
        '512' => 521 # note difference
      }

      module_function

      def der_to_signature(der, sha_bits)
        signature_pair = OpenSSL::ASN1.decode(der).value
        width = per_part_byte_count(sha_bits)
        signature_pair.map { |part| part.value.to_s(2).rjust(width, "\x00") }.join
      end

      def signature_to_der(signature, sha_bits)
        hsh = destructured_sig(signature, sha_bits)
        asn1_seq = OpenSSL::ASN1::Sequence.new([
          asn1_int(hsh[:r]),
          asn1_int(hsh[:s])
        ])
        asn1_seq.to_der
      end

      def per_part_byte_count(sha_bits)
        bits = KEY_BITS[sha_bits]
        bits ? (bits + 7) / 8 : fail('Invalid sha_bits')
      end

      def destructured_sig(signature, sha_bits)
        n = per_part_byte_count(sha_bits)
        fail('Invalid signature length') unless signature.length == n * 2
        {
          r: signature[0, n],
          s: signature[n, n]
        }
      end

      def asn1_int(int)
        OpenSSL::ASN1::Integer.new(OpenSSL::BN.new int, 2)
      end

      private_class_method :per_part_byte_count,
        :destructured_sig,
        :asn1_int
    end
  end
end
