require 'json_web_token/algorithm/rsa_util'
require 'json_web_token/jwa'
require 'support/ecdsa_key'

module JsonWebToken

  RsaUtil = JsonWebToken::Algorithm::RsaUtil

  describe Jwa do
    let(:signing_input) { '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}' }
    shared_examples_for 'w #verify?' do
      it 'true' do
        expect(Jwa.verify? mac, algorithm, verifying_key, signing_input).to be true
      end
    end
    context '#sign' do
      let(:mac) { Jwa.sign(algorithm, signing_key, signing_input) }
      describe 'HS256' do
        let(:algorithm) { 'HS256' }
        let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        let(:verifying_key) { signing_key }
        it_behaves_like 'w #verify?'

        it 'returns a 32-byte MAC' do
          expect(mac.bytesize).to eql 32
        end
      end

      describe 'RS256' do
        let(:algorithm) { 'RS256' }
        let(:path_to_keys) { 'spec/fixtures/rsa' }
        let(:signing_key) { RsaUtil.private_key(path_to_keys) }
        let(:verifying_key) { RsaUtil.public_key(path_to_keys) }
        it_behaves_like 'w #verify?'

        it 'returns a 256-byte MAC' do
          expect(mac.bytesize).to eql 256
        end
      end

      describe 'ES256' do
        let(:algorithm) { 'ES256' }
        it 'w #verify? true, returns a 64-byte MAC' do
          private_key = EcdsaKey.curve_new('256')
          public_key_str = EcdsaKey.public_key_str(private_key)
          public_key = EcdsaKey.public_key_new('256', public_key_str)

          mac = Jwa.sign(algorithm, private_key, signing_input)
          expect(Jwa.verify? mac, algorithm, public_key, signing_input).to be true

          expect(mac.bytesize).to eql 64
        end
      end
    end

    context 'param validation' do
      context 'w HS256 key' do
        let(:shared_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        describe 'unrecognized algorithm' do
          ['HT256', 'HS257', '', nil].each do |elt|
            let(:algorithm) { "#{elt}" }
            it 'raises' do
              expect { Jwa.sign(algorithm, shared_key, signing_input) }
                .to raise_error(RuntimeError, 'Unrecognized algorithm')
            end
          end
        end
      end
    end
  end
end
