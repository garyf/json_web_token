require 'json_web_token/jwt'
require 'support/ecdsa_key'
require 'support/plausible_jwt'

module JsonWebToken
  describe Jwt do
    context '#sign' do
      shared_examples_for 'does #verify' do
        it 'w a claims set' do
          jwt = Jwt.sign(claims, sign_options)
          expect(Jwt.verify(jwt, verify_options)[:ok]).to include(claims)
        end
      end

      shared_examples_for 'return a jwt' do
        it 'that is plausible' do
          jwt = Jwt.sign(claims, sign_options)
          expect(plausible_message_signature? jwt).to be true
        end
      end

      context 'w claims' do
        let(:claims) { { iss: 'joe', exp: 1300819380, :'http://example.com/is_root' => true} }
        context 'w HS256 keys' do
          let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
          let(:verifying_key) { signing_key }
          let(:verify_options) { {key: verifying_key} }
          describe 'default header' do
            let(:sign_options) { {key: signing_key} }
            it_behaves_like 'does #verify'
            it_behaves_like 'return a jwt'
          end

          describe 'w alg option' do
            let(:sign_options) { {alg: 'HS256', key: signing_key} }
            it_behaves_like 'does #verify'
            it_behaves_like 'return a jwt'
          end

          describe 'w alg: nil option' do
            let(:sign_options) { {alg: nil, key: signing_key} }
            it_behaves_like 'does #verify'
            it_behaves_like 'return a jwt'
          end

          describe "w alg empty string option" do
            let(:sign_options) { {alg: '', key: signing_key} }
            it_behaves_like 'does #verify'
            it_behaves_like 'return a jwt'
          end

          describe "w alg: 'none' option" do
            let(:sign_options) { {alg: 'none', key: signing_key} }
            it 'raises' do
              jwt = Jwt.sign(claims, sign_options)
              expect { Jwt.verify(jwt, verify_options) }
                .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
            end
          end
        end

        describe 'w/o key w default header alg' do
          it 'raises' do
            expect { Jwt.sign(claims, {}) }
              .to raise_error(RuntimeError, 'Invalid shared key')
          end
        end

        describe 'w HS256 key changed' do
          let(:sign_options) { {alg: 'HS256', key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'} }
          let(:changed_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9Z' }
          let(:verify_options) { {key: verifying_key} }
          it 'raises' do
            jwt = Jwt.sign(claims, sign_options)
            expect(Jwt.verify jwt, {key: changed_key}).to include(error: 'invalid')
          end
        end

        context "w ES256 'alg' header parameter" do
          let(:algorithm) { 'ES256' }
          describe 'w passing a matching algorithm to #verify' do
            it 'is verified and plausible' do
              private_key = EcdsaKey.curve_new('256')
              public_key_str = EcdsaKey.public_key_str(private_key)
              public_key = EcdsaKey.public_key_new('256', public_key_str)

              sign_options = {alg: algorithm, key: private_key}
              jwt = Jwt.sign(claims, sign_options)

              verify_options = {alg: algorithm, key: public_key}
              expect(Jwt.verify(jwt, verify_options)[:ok]).to eql claims

              expect(plausible_message_signature? jwt, 64).to be true
            end
          end
        end

        context 'w/o key' do
          context "w alg: 'none' header parameter" do
            let(:sign_options) { {alg: 'none'} }
            describe "w verify alg: 'none'" do
              let(:verify_options) { {alg: 'none'} }
              it 'verifies a plausible unsecured jws' do
                jwt = Jwt.sign(claims, sign_options)
                expect(Jwt.verify(jwt, verify_options)[:ok]).to include(claims)
                expect(plausible_unsecured_message? jwt).to be true
              end
            end

            describe 'w default verify alg' do
              it 'raises' do
                jwt = Jwt.sign(claims, sign_options)
                expect { Jwt.verify(jwt, {alg: nil}) }
                  .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
              end
            end
          end
        end
      end

      context 'param validation' do
        let(:options) { {key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C'} }
        shared_examples_for 'w/o claims' do
          it 'raises' do
            expect { Jwt.sign(claims, options) }
              .to raise_error(RuntimeError, 'Claims blank')
          end
        end

        describe 'w claims nil' do
          let(:claims) { nil }
          it_behaves_like 'w/o claims'
        end

        describe 'w claims an empty string' do
          let(:claims) { '' }
          it_behaves_like 'w/o claims'
        end
      end
    end
  end
end
