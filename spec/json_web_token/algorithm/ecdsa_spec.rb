require 'json_web_token/algorithm/ecdsa'
require 'support/ecdsa_key'

module JsonWebToken
  module Algorithm
    describe Ecdsa do
      describe 'detect changed signature or data' do
        let(:signing_input_0) { 'signing_input_0' }
        let(:signing_input_1) { 'signing_input_1' }
        shared_examples_for '#signed' do
          it 'is #verified?' do
            private_key_0 = EcdsaKey.curve_new(sha_bits)
            public_key_str_0 = EcdsaKey.public_key_str(private_key_0)
            public_key_0 = EcdsaKey.public_key_new(sha_bits, public_key_str_0)

            mac_0 = Ecdsa.signed(sha_bits, private_key_0, signing_input_0)
            expect(mac_0.bytes.count).to eql expected_mac_byte_count
            expect(Ecdsa.verified? mac_0, sha_bits, public_key_0, signing_input_0).to be true

            private_key_1 = EcdsaKey.curve_new(sha_bits)
            public_key_str_1 = EcdsaKey.public_key_str(private_key_1)
            public_key_1 = EcdsaKey.public_key_new(sha_bits, public_key_str_1)

            expect(Ecdsa.verified? mac_0, sha_bits, public_key_0, signing_input_1).to be false
            expect(Ecdsa.verified? mac_0, sha_bits, public_key_1, signing_input_0).to be false
            expect(Ecdsa.verified? mac_0, sha_bits, public_key_1, signing_input_1).to be false

            mac_1 = Ecdsa.signed(sha_bits, private_key_1, signing_input_1)
            expect(Ecdsa.verified? mac_1, sha_bits, public_key_0, signing_input_0).to be false
            expect(Ecdsa.verified? mac_1, sha_bits, public_key_0, signing_input_1).to be false
            expect(Ecdsa.verified? mac_1, sha_bits, public_key_1, signing_input_0).to be false
            expect(Ecdsa.verified? mac_1, sha_bits, public_key_1, signing_input_1).to be true
          end
        end

        describe 'ES256' do
          let(:sha_bits) { '256' }
          let(:expected_mac_byte_count) { 64 }
          it_behaves_like '#signed'
        end

        describe 'ES384' do
          let(:sha_bits) { '384' }
          let(:expected_mac_byte_count) { 96 }
          it_behaves_like '#signed'
        end

        describe 'ES512' do
          let(:sha_bits) { '512' }
          let(:expected_mac_byte_count) { 132 }
          it_behaves_like '#signed'
        end
      end
    end
  end
end
