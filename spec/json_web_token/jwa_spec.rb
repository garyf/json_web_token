require 'json_web_token/jwa'

module JsonWebToken
  describe Jwa do
    context 'detect changed signing_input or MAC' do
      let(:signing_input) { 'signing_input' }
      let(:changed_signing_input) { 'changed_signing_input' }
      shared_examples_for '#signed' do
        it 'is #verified?' do
          mac = Jwa.signed(algorithm, signing_key, signing_input)
          expect(Jwa.verified? mac, algorithm, verifying_key, signing_input).to be true
          expect(Jwa.verified? mac, algorithm, verifying_key, changed_signing_input).to be false

          changed_mac = Jwa.signed(algorithm, signing_key, changed_signing_input)
          expect(Jwa.verified? changed_mac, algorithm, verifying_key, signing_input).to be false
        end
      end

      describe 'HS256' do
        let(:algorithm) { 'HS256' }
        let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        let(:verifying_key) { signing_key }
        it_behaves_like '#signed'
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

        describe 'HS256' do
          let(:algorithm) { 'HS256' }
          it 'returns a 32-byte MAC string' do
            mac = Jwa.signed(algorithm, key, data)
            expect(mac.bytesize).to eql 32
            expect(mac.class).to eql String
          end
        end
      end
    end
  end
end
