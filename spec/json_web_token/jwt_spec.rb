require 'json_web_token/jwt'
require 'support/plausible_jwt'

module JsonWebToken
  describe Jwt do
    context '#create' do
      shared_examples_for 'w #validate' do
        it 'verified' do
          jwt = Jwt.create(claims, options)
          expect(Jwt.validate jwt, options).to include(claims)
        end
      end

      shared_examples_for 'return message signature' do
        it 'plausible' do
          serialized_output = Jwt.create(claims, options)
          expect(plausible_message_signature? serialized_output).to be true
        end
      end

      shared_examples_for 'return unsecured jws' do
        it 'plausible' do
          serialized_output = Jwt.create(claims, options)
          expect(plausible_unsecured_jws? serialized_output).to be true
        end
      end

      context 'w claims' do
        let(:claims) { {exp: 'tomorrow'} }
        context 'w key' do
          let(:key) { 'this_a_32_character_private_key!' }
          describe 'default header' do
            let(:options) { {key: key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end

          describe 'passing header parameters' do
            let(:options) { {typ: 'JWT', alg: 'HS256', key: key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end

          describe "w 'alg':'none' header parameter" do
            let(:options) { {typ: 'JWT', alg: 'none', key: key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return unsecured jws'
          end

          describe "w 'alg':'nil' header parameter" do
            let(:options) { {alg: nil, key: key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end

          describe "w 'alg':'' header parameter" do
            let(:options) { {alg: nil, key: key} }
            it_behaves_like 'w #validate'
            it_behaves_like 'return message signature'
          end
        end

        context 'w/o key' do
          let(:options) { {typ: 'JWT', alg: 'none'} }
          describe "w 'alg':'none' header parameter" do
            it_behaves_like 'w #validate'
            it_behaves_like 'return unsecured jws'
          end
        end
      end

      shared_examples_for 'claims not provided' do
        it 'raises' do
          expect { Jwt.create(claims, options) }
            .to raise_error(RuntimeError, 'Claims not provided')
        end
      end

      context 'w secret' do
        let(:options) { {key: 'secret'} }
        describe 'w claims nil' do
          let(:claims) { nil }
          it_behaves_like 'claims not provided'
        end

        describe "w claims ''" do
          let(:claims) { '' }
          it_behaves_like 'claims not provided'
        end
      end
    end
  end
end
