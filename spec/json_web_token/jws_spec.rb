require 'json_web_token/jws'
require 'support/ecdsa_key'

module JsonWebToken
  describe Jws do
    context 'w payload' do
      let(:payload) { '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}' }
      context '#sign' do
        shared_examples_for 'does #verify' do
          it 'w a jws' do
            jws = Jws.sign(header, payload, signing_key)
            expect(Jws.verify jws, algorithm, verifying_key).to include({ok: jws})
          end
        end

        context 'w HS256 keys' do
          let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
          let(:verifying_key) { signing_key }
          context "w HS256 'alg' header parameter" do
            let(:header) { {alg: 'HS256'} }
            context 'w passing a matching algorithm to #verify' do
              let(:algorithm) { 'HS256' }
              it_behaves_like 'does #verify'

              describe 'w/o passing key to #verify' do
                it 'returns error' do
                  jws = Jws.sign(header, payload, signing_key)
                  expect(Jws.verify jws, algorithm, nil).to include({error: 'invalid'})
                end
              end

              describe 'w passing a changed key to #verify' do
                let(:changed_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9Z' }
                it 'returns error' do
                  jws = Jws.sign(header, payload, signing_key)
                  expect(Jws.verify jws, algorithm, changed_key).to include({error: 'invalid'})
                end
              end
            end

            describe 'w/o passing a matching algorithm to #verify' do
              let(:algorithm) { 'RS256' }
              it 'raises' do
                jws = Jws.sign(header, payload, signing_key)
                expect { Jws.verify(jws, algorithm, verifying_key) }
                  .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
              end
            end
          end
        end

        context "w ES256 'alg' header parameter" do
          let(:header) { {alg: 'ES256'} }
          describe 'w passing a matching algorithm to #verify' do
            let(:algorithm) { 'ES256' }
            it 'w a jws' do
              private_key = EcdsaKey.curve_new('256')
              public_key_str = EcdsaKey.public_key_str(private_key)
              public_key = EcdsaKey.public_key_new('256', public_key_str)

              jws = Jws.sign(header, payload, private_key)
              expect(Jws.verify jws, algorithm, public_key).to include({ok: jws})
            end
          end
        end
      end

      context 'header validation' do
        let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
        describe "w/o a recognized 'alg' header parameter" do
          let(:header) { {alg: 'HS257'} }
          it 'raises' do
            expect { Jws.sign(header, payload, signing_key) }
              .to raise_error(RuntimeError, 'Unrecognized algorithm')
          end
        end

        describe "w/o a required 'alg' header parameter" do
          let(:header) { {typ: 'JWT'} }
          it 'raises' do
            expect { Jws.sign(header, payload, signing_key) }
              .to raise_error(RuntimeError, "Missing required 'alg' header parameter")
          end
        end
      end

      context '#unsecured_message' do
        context 'w valid header' do
          let(:header) { {alg: 'none'} }
          describe 'w passing a matching algorithm to #verify' do
            let(:algorithm) { 'none' }
            it 'w a jws' do
              jws = Jws.unsecured_message(header, payload)
              expect(Jws.verify jws, algorithm).to include({ok: jws})
            end
          end

          describe 'w/o passing a matching algorithm to #verify' do
            let(:algorithm) { 'HS256' }
            let(:verifying_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
            it 'raises' do
              jws = Jws.unsecured_message(header, payload)
              expect { Jws.verify(jws, algorithm, verifying_key) }
                .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
            end
          end
        end

        describe 'w invalid header' do
          let(:header) { {alg: 'HS256'} }
          it 'raises' do
            expect { Jws.unsecured_message(header, payload) }
              .to raise_error(RuntimeError, "Invalid 'alg' header parameter")
          end
        end
      end
    end
  end
end
