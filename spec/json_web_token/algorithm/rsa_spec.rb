require 'json_web_token/algorithm/rsa'
require 'json_web_token/algorithm/rsa_util'

module JsonWebToken
  module Algorithm
    describe Rsa do
      let(:signing_input_0) { '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}' }
      let(:signing_input_1) { '{"iss":"mike","exp":1300819380,"http://example.com/is_root":false}' }
      let(:path_to_keys) { 'spec/fixtures/rsa' }
      context 'detect changed signing_input or MAC' do
        let(:private_key) { RsaUtil.private_key(path_to_keys) }
        let(:public_key) { RsaUtil.public_key(path_to_keys) }
        shared_examples_for '#sign' do
          it 'does #verify?' do
            mac = Rsa.sign(sha_bits, private_key, signing_input_0)
            expect(Rsa.verify? mac, sha_bits, public_key, signing_input_0).to be true
            expect(Rsa.verify? mac, sha_bits, public_key, signing_input_1).to be false

            changed_mac = Rsa.sign(sha_bits, private_key, signing_input_1)
            expect(Rsa.verify? changed_mac, sha_bits, public_key, signing_input_0).to be false
          end
        end

        context 'RS256' do
          let(:sha_bits) { '256' }
          it_behaves_like '#sign'

          describe 'changed key' do
            let(:changed_public_key) { RsaUtil.public_key(path_to_keys, 'public_key_alt.pem') }
            it 'fails to #verify?' do
              mac = Rsa.sign(sha_bits, private_key, signing_input_0)
              expect(Rsa.verify? mac, sha_bits, public_key, signing_input_0).to be true
              expect(Rsa.verify? mac, sha_bits, changed_public_key, signing_input_0).to be false
            end
          end
        end

        describe 'RS384' do
          let(:sha_bits) { '384' }
          it_behaves_like '#sign'
        end

        describe 'RS512' do
          let(:sha_bits) { '512' }
          it_behaves_like '#sign'
        end
      end

      context 'param validation' do
        shared_examples_for 'invalid private_key' do
          it 'raises' do
            expect { Rsa.sign(sha_bits, private_key, signing_input_0) }
              .to raise_error(RuntimeError, 'Invalid key: RSA modulus too small')
          end
        end

        context 'private_key bit size < KEY_BITS_MIN (2048)' do
          let(:private_key) { RsaUtil.private_key(path_to_keys, 'private_key_weak.pem') }
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
            mac = Rsa.sign(sha_bits, private_key, signing_input_0)
            expect(mac.bytesize).to eql 256
          end
        end

        context 'private_key bits (2048) == KEY_BITS_MIN (2048)' do
          let(:private_key) { RsaUtil.private_key(path_to_keys) }
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
              expect { Rsa.sign(sha_bits, private_key, signing_input_0) }.to raise_error(NoMethodError)
            end
          end
        end

        describe 'w unrecognized sha_bits' do
          let(:sha_bits) { '257' }
          let(:private_key) { 'private_key' }
          it 'raises' do
            expect { Rsa.sign(sha_bits, private_key, signing_input_0) }
              .to raise_error(RuntimeError, 'Invalid sha_bits')
          end
        end
      end
    end
  end
end
