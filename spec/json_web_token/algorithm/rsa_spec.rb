require 'json_web_token/algorithm/rsa'

module JsonWebToken
  module Algorithm
    describe Rsa do
      context 'detect changed signing_input or MAC' do
        let(:private_key) { OpenSSL::PKey::RSA.generate(Rsa::KEY_BITS_MIN) }
        let(:public_key) { private_key.public_key }
        let(:signing_input) { 'signing_input' }
        let(:changed_signing_input) { 'changed_signing_input' }
        shared_examples_for '#signed' do
          it 'is #verified?' do
            mac = Rsa.signed(sha_bits, private_key, signing_input)
            expect(Rsa.verified? mac, sha_bits, public_key, signing_input).to be true
            expect(Rsa.verified? mac, sha_bits, public_key, changed_signing_input).to be false

            changed_mac = Rsa.signed(sha_bits, private_key, changed_signing_input)
            expect(Rsa.verified? changed_mac, sha_bits, public_key, signing_input).to be false
          end
        end

        context 'RS256' do
          let(:sha_bits) { '256' }
          it_behaves_like '#signed'

          describe 'changed key' do
            let(:changed_public_key) { OpenSSL::PKey::RSA.generate(Rsa::KEY_BITS_MIN).public_key }
            let(:data) { 'data' }
            it 'fails #verified?' do
              mac = Rsa.signed(sha_bits, private_key, data)
              expect(Rsa.verified? mac, sha_bits, public_key, data).to be true
              expect(Rsa.verified? mac, sha_bits, changed_public_key, data).to be false
            end
          end
        end

        describe 'RS384' do
          let(:sha_bits) { '384' }
          it_behaves_like '#signed'
        end

        describe 'RS512' do
          let(:sha_bits) { '512' }
          it_behaves_like '#signed'
        end
      end

      context 'param validation' do
        let(:data) { 'data' }
        shared_examples_for 'invalid private_key' do
          it 'raises' do
            expect { Rsa.signed(sha_bits, private_key, data) }.to raise_error(RuntimeError, 'Invalid private key')
          end
        end

        context 'private_key bit size (2047) < KEY_BITS_MIN (2048)' do
          let(:private_key) { OpenSSL::PKey::RSA.generate(Rsa::KEY_BITS_MIN - 1) }
          describe 'w 256 sha_bits' do
            let(:sha_bits) { '256' }
            it_behaves_like 'invalid private_key'
          end

          describe 'w 384 sha_bits' do
            let(:sha_bits) { '384' }
            it_behaves_like 'invalid private_key'
          end

          describe 'w 512 sha_bits' do
            let(:sha_bits) { '512' }
            it_behaves_like 'invalid private_key'
          end
        end

        shared_examples_for '2048 bit private_key' do
          it 'returns a 256-byte MAC string' do
            mac = Rsa.signed(sha_bits, private_key, data)
            expect(mac.bytesize).to eql 256
            expect(mac.class).to eql String
          end
        end

        context 'private_key bits (2048) == KEY_BITS_MIN (2048)' do
          let(:private_key) { OpenSSL::PKey::RSA.generate(Rsa::KEY_BITS_MIN) }
          describe 'w 256 sha_bits' do
            let(:sha_bits) { '256' }
            it_behaves_like '2048 bit private_key'
          end

          describe 'w 384 sha_bits' do
            let(:sha_bits) { '384' }
            it_behaves_like '2048 bit private_key'
          end

          describe 'w 512 sha_bits' do
            let(:sha_bits) { '512' }
            it_behaves_like '2048 bit private_key'
          end
        end

        context 'blank private_key' do
          let(:sha_bits) { '256' }
          describe 'nil' do
            let(:private_key) { nil }
            it_behaves_like 'invalid private_key'
          end

          describe 'empty string' do
            let(:private_key) { '' }
            it 'raises' do
              expect { Rsa.signed(sha_bits, private_key, data) }.to raise_error(NoMethodError)
            end
          end
        end

        describe 'w unrecognized sha_bits' do
          let(:sha_bits) { '257' }
          let(:private_key) { 'private_key' }
          it 'raises' do
            expect { Rsa.signed(sha_bits, private_key, data) }
              .to raise_error(RuntimeError, 'Invalid sha_bits')
          end
        end
      end
    end
  end
end
