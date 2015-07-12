require 'json_web_token/algorithm/hmac'

module JsonWebToken
  module Algorithm
    describe Hmac do
      context 'detect changed signing_input or MAC' do
        let(:signing_input) { 'signing_input' }
        let(:changed_signing_input) { 'changed_signing_input' }
        shared_examples_for '#signed' do
          it 'is #verified?' do
            mac = Hmac.signed(sha_bits, key, signing_input)
            expect(Hmac.verified? mac, sha_bits, key, signing_input).to be true
            expect(Hmac.verified? mac, sha_bits, key, changed_signing_input).to be false

            changed_mac = Hmac.signed(sha_bits, key, changed_signing_input)
            expect(Hmac.verified? changed_mac, sha_bits, key, signing_input).to be false
          end
        end

        describe 'HS256' do
          let(:sha_bits) { '256' }
          let(:key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
          it_behaves_like '#signed'
        end

        describe 'HS384' do
          let(:sha_bits) { '384' }
          let(:key) { 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS' }
          it_behaves_like '#signed'
        end

        describe 'HS512' do
          let(:sha_bits) { '512' }
          let(:key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hc' }
          it_behaves_like '#signed'
        end
      end

      describe 'changed key' do
        let(:sha_bits) { '256' }
        let(:key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        let(:changed_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9Z' }
        let(:data) { 'data' }
        it 'fails #verified?' do
          mac = Hmac.signed(sha_bits, key, data)
          expect(Hmac.verified? mac, sha_bits, key, data).to be true
          expect(Hmac.verified? mac, sha_bits, changed_key, data).to be false
        end
      end

      context 'param validation' do
        let(:data) { 'data' }
        shared_examples_for 'invalid key' do
          it 'raises' do
            expect { Hmac.signed(sha_bits, key, data) }.to raise_error(RuntimeError, 'Invalid key')
          end
        end

        context 'w 256 sha_bits' do
          let(:sha_bits) { '256' }
          describe 'key nil' do
            let(:key) { nil }
            it_behaves_like 'invalid key'
          end

          describe "key 'empty string'" do
            let(:key) { '' }
            it_behaves_like 'invalid key'
          end

          describe 'key length (31) < MAC length (32)' do
            let(:key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9' }
            it_behaves_like 'invalid key'
          end

          describe 'key length (32) == MAC length (32)' do
            let(:key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
            it 'returns a 32-byte MAC string' do
              mac = Hmac.signed(sha_bits, key, data)
              expect(mac.bytesize).to eql 32
            end
          end
        end

        context 'w 384 sha_bits' do
          let(:sha_bits) { '384' }
          describe 'key length (47) < MAC length (48)' do
            let(:key) { 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1q' }
            it_behaves_like 'invalid key'
          end

          describe 'key length (48) == MAC length (48)' do
            let(:key) { 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS' }
            it 'returns a 48-byte MAC string' do
              mac = Hmac.signed(sha_bits, key, data)
              expect(mac.bytesize).to eql 48
            end
          end
        end

        context 'w 512 sha_bits' do
          let(:sha_bits) { '512' }
          describe 'key length (63) < MAC length (64)' do
            let(:key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4h' }
            it_behaves_like 'invalid key'
          end

          describe 'key length (64) == MAC length (64)' do
            let(:key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hc' }
            it 'returns a 64-byte MAC string' do
              mac = Hmac.signed(sha_bits, key, data)
              expect(mac.bytesize).to eql 64
            end
          end
        end

        describe 'w unrecognized sha_bits' do
          let(:sha_bits) { '257' }
          let(:key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hc' }
          it 'raises' do
            expect { Hmac.signed(sha_bits, key, data) }
              .to raise_error(RuntimeError, 'Invalid sha_bits')
          end
        end
      end
    end
  end
end
