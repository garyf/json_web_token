require 'json_web_token/jwt'
require 'support/ecdsa_key'
require 'support/plausible_jwt'

module JsonWebToken
  describe Jwt do
    context '#create' do
      shared_examples_for 'w #validate' do
        it 'is verified' do
          jwt = Jwt.create(claims, create_options)
          expect(Jwt.validate jwt, validate_options).to include(claims)
        end
      end

      shared_examples_for 'return message signature' do
        it 'plausible' do
          jwt = Jwt.create(claims, create_options)
          expect(plausible_message_signature? jwt).to be true
        end
      end

      context 'w claims' do
        let(:claims) { {exp: 'tomorrow'} }
        context 'w HS256 keys' do
          let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
          let(:verifying_key) { signing_key }
          let(:validate_options) { {key: verifying_key} }
          describe 'default header' do
            let(:create_options) { {key: signing_key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end

          describe 'w alg option' do
            let(:create_options) { {alg: 'HS256', key: signing_key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end

          describe 'w alg: nil option' do
            let(:create_options) { {alg: nil, key: signing_key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end

          describe "w alg empty string option" do
            let(:create_options) { {alg: '', key: signing_key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end

          describe "w alg: 'none' option" do
            let(:create_options) { {alg: 'none', key: signing_key} }
            it 'raises' do
              jwt = Jwt.create(claims, create_options)
              expect { Jwt.validate(jwt, validate_options) }
                .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
            end
          end
        end

        context 'w RS256 keys' do
          let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
          let(:verifying_key) { signing_key.public_key }
          let(:validate_options) { {alg: 'RS256', key: verifying_key} }
          describe 'passing matching options' do
            let(:create_options) { {alg: 'RS256', key: signing_key} }
            it_behaves_like 'w #validate'

            it 'plausible' do
              jwt = Jwt.create(claims, create_options)
              expect(plausible_message_signature? jwt, 256).to be true
            end
          end
        end

        context "w ES256 'alg' header parameter" do
          let(:algorithm) { 'ES256' }
          describe 'w passing a matching algorithm to #validate' do
            it 'is verified and plausible' do
              private_key = EcdsaKey.curve_new('256')
              public_key_str = EcdsaKey.public_key_str(private_key)
              public_key = EcdsaKey.public_key_new('256', public_key_str)

              create_options = {alg: algorithm, key: private_key}
              jwt = Jwt.create(claims, create_options)

              validate_options = {alg: algorithm, key: public_key}
              expect(Jwt.validate jwt, validate_options).to include(claims)

              expect(plausible_message_signature? jwt, 64).to be true
            end
          end
        end

        context 'w/o key' do
          context "w alg: 'none' header parameter" do
            let(:create_options) { {alg: 'none'} }
            describe "w validate alg: 'none'" do
              let(:validate_options) { {alg: 'none'} }
              it 'validates a plausible unsecured jws' do
                jwt = Jwt.create(claims, create_options)
                expect(Jwt.validate jwt, validate_options).to include(claims)
                expect(plausible_unsecured_jws? jwt).to be true
              end
            end

            describe 'w default validate alg' do
              it 'raises' do
                jwt = Jwt.create(claims, create_options)
                expect { Jwt.validate(jwt) }
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
            expect { Jwt.create(claims, options) }
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
