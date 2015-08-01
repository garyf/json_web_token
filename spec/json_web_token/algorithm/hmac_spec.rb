require 'json_web_token/algorithm/hmac'

module JsonWebToken
  module Algorithm
    describe Hmac do
      let(:signing_input_0) { '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}' }
      let(:signing_input_1) { '{"iss":"mike","exp":1300819380,"http://example.com/is_root":false}' }
      context 'detect changed signing_input or MAC' do
        shared_examples_for '#sign' do
          it 'does #verify?' do
            mac = Hmac.sign(sha_bits, shared_key, signing_input_0)
            expect(Hmac.verify? mac, sha_bits, shared_key, signing_input_0).to be true
            expect(Hmac.verify? mac, sha_bits, shared_key, signing_input_1).to be false

            changed_mac = Hmac.sign(sha_bits, shared_key, signing_input_1)
            expect(Hmac.verify? changed_mac, sha_bits, shared_key, signing_input_0).to be false
          end
        end

        describe 'HS256' do
          let(:sha_bits) { '256' }
          let(:shared_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
          it_behaves_like '#sign'
        end

        describe 'HS384' do
          let(:sha_bits) { '384' }
          let(:shared_key) { 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS' }
          it_behaves_like '#sign'
        end

        describe 'HS512' do
          let(:sha_bits) { '512' }
          let(:shared_key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hc' }
          it_behaves_like '#sign'
        end
      end

      describe 'changed key' do
        let(:sha_bits) { '256' }
        let(:shared_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        let(:changed_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9Z' }
        it 'fails to #verify?' do
          mac = Hmac.sign(sha_bits, shared_key, signing_input_0)
          expect(Hmac.verify? mac, sha_bits, shared_key, signing_input_0).to be true
          expect(Hmac.verify? mac, sha_bits, changed_key, signing_input_0).to be false
        end
      end

      context 'param validation' do
        shared_examples_for 'invalid key' do
          it 'raises' do
            expect { Hmac.sign(sha_bits, shared_key, signing_input_0) }
              .to raise_error(RuntimeError, 'Invalid shared key')
          end
        end

        context 'w 256 sha_bits' do
          let(:sha_bits) { '256' }
          describe 'shared_key nil' do
            let(:shared_key) { nil }
            it_behaves_like 'invalid key'
          end

          describe "shared_key 'empty string'" do
            let(:shared_key) { '' }
            it_behaves_like 'invalid key'
          end

          describe 'shared_key length (31) < MAC length (32)' do
            let(:shared_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9' }
            it_behaves_like 'invalid key'
          end

          describe 'shared_key length (32) == MAC length (32)' do
            let(:shared_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
            it 'returns a 32-byte MAC string' do
              mac = Hmac.sign(sha_bits, shared_key, signing_input_0)
              expect(mac.bytesize).to eql 32
            end
          end
        end

        context 'w 384 sha_bits' do
          let(:sha_bits) { '384' }
          describe 'shared_key length (47) < MAC length (48)' do
            let(:shared_key) { 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1q' }
            it_behaves_like 'invalid key'
          end

          describe 'shared_key length (48) == MAC length (48)' do
            let(:shared_key) { 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS' }
            it 'returns a 48-byte MAC string' do
              mac = Hmac.sign(sha_bits, shared_key, signing_input_0)
              expect(mac.bytesize).to eql 48
            end
          end
        end

        context 'w 512 sha_bits' do
          let(:sha_bits) { '512' }
          describe 'shared_key length (63) < MAC length (64)' do
            let(:shared_key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4h' }
            it_behaves_like 'invalid key'
          end

          describe 'shared_key length (64) == MAC length (64)' do
            let(:shared_key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hc' }
            it 'returns a 64-byte MAC string' do
              mac = Hmac.sign(sha_bits, shared_key, signing_input_0)
              expect(mac.bytesize).to eql 64
            end
          end
        end

        describe 'w unrecognized sha_bits' do
          let(:sha_bits) { '257' }
          let(:shared_key) { 'ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hc' }
          it 'raises' do
            expect { Hmac.sign(sha_bits, shared_key, signing_input_0) }
              .to raise_error(RuntimeError, 'Invalid sha_bits')
          end
        end
      end
    end
  end
end
