require 'json_web_token/algorithm/ecdsa'
require 'support/ecdsa_key'

module JsonWebToken
  module Algorithm
    describe Ecdsa do
      let(:signing_input_0) { '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}' }
      let(:signing_input_1) { '{"iss":"mike","exp":1300819380,"http://example.com/is_root":false}' }
      describe 'detect changed signature or data' do
        shared_examples_for '#sign' do
          it 'does #verify?' do
            private_key_0 = EcdsaKey.curve_new(sha_bits)
            public_key_str_0 = EcdsaKey.public_key_str(private_key_0)
            public_key_0 = EcdsaKey.public_key_new(sha_bits, public_key_str_0)

            mac_0 = Ecdsa.sign(sha_bits, private_key_0, signing_input_0)
            expect(mac_0.bytes.count).to eql expected_mac_byte_count
            expect(Ecdsa.verify? mac_0, sha_bits, public_key_0, signing_input_0).to be true

            private_key_1 = EcdsaKey.curve_new(sha_bits)
            public_key_str_1 = EcdsaKey.public_key_str(private_key_1)
            public_key_1 = EcdsaKey.public_key_new(sha_bits, public_key_str_1)

            expect(Ecdsa.verify? mac_0, sha_bits, public_key_0, signing_input_1).to be false
            expect(Ecdsa.verify? mac_0, sha_bits, public_key_1, signing_input_0).to be false
            expect(Ecdsa.verify? mac_0, sha_bits, public_key_1, signing_input_1).to be false

            mac_1 = Ecdsa.sign(sha_bits, private_key_1, signing_input_1)
            expect(Ecdsa.verify? mac_1, sha_bits, public_key_0, signing_input_0).to be false
            expect(Ecdsa.verify? mac_1, sha_bits, public_key_0, signing_input_1).to be false
            expect(Ecdsa.verify? mac_1, sha_bits, public_key_1, signing_input_0).to be false
            expect(Ecdsa.verify? mac_1, sha_bits, public_key_1, signing_input_1).to be true
          end
        end

        describe 'ES256' do
          let(:sha_bits) { '256' }
          let(:expected_mac_byte_count) { 64 }
          it_behaves_like '#sign'
        end

        describe 'ES384' do
          let(:sha_bits) { '384' }
          let(:expected_mac_byte_count) { 96 }
          it_behaves_like '#sign'
        end

        describe 'ES512' do
          let(:sha_bits) { '512' }
          let(:expected_mac_byte_count) { 132 }
          it_behaves_like '#sign'
        end
      end
    end
  end
end
