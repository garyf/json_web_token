require 'json_web_token/jwa'
require 'support/ecdsa_key'

module JsonWebToken
  describe Jwa do
    shared_examples_for 'w #verified?' do
      it 'true' do
        expect(Jwa.verified? mac, algorithm, verifying_key, signing_input).to be true
      end
    end
    context '#signed' do
      let(:signing_input) { 'signing_input' }
      let(:mac) { Jwa.signed(algorithm, private_key, signing_input) }
      describe 'HS256' do
        let(:algorithm) { 'HS256' }
        let(:private_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        let(:verifying_key) { private_key }
        it_behaves_like 'w #verified?'

        it 'returns a 32-byte MAC' do
          expect(mac.bytesize).to eql 32
        end
      end

      describe 'RS256' do
        let(:algorithm) { 'RS256' }
        let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
        let(:verifying_key) { private_key.public_key }
        it_behaves_like 'w #verified?'

        it 'returns a 256-byte MAC' do
          expect(mac.bytesize).to eql 256
        end
      end

      describe 'ES256' do
        let(:algorithm) { 'ES256' }
        it 'w #verified? true, returns a 64-byte MAC' do
          private_key = EcdsaKey.curve_new('256')
          public_key_str = EcdsaKey.public_key_str(private_key)
          public_key = EcdsaKey.public_key_new('256', public_key_str)

          mac = Jwa.signed(algorithm, private_key, signing_input)
          expect(Jwa.verified? mac, algorithm, public_key, signing_input).to be true

          expect(mac.bytesize).to eql 64
        end
      end
    end

    context 'param validation' do
      let(:data) { 'data' }
      context 'w HS256 key' do
        let(:key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        describe 'unrecognized algorithm' do
          ['HT256', 'HS257', '', nil].each do |elt|
            let(:algorithm) { "#{elt}" }
            it 'raises' do
              expect { Jwa.signed(algorithm, key, data) }
                .to raise_error(RuntimeError, 'Unrecognized algorithm')
            end
          end
        end
      end
    end
  end
end
