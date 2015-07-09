require 'json_web_token'

describe JsonWebToken do
  context '#create' do
    let(:claims) { {exp: 'tomorrow'} }
    shared_examples_for 'w #validate' do
      it 'is verified' do
        jwt = JsonWebToken.create(claims, create_options)
        expect(JsonWebToken.validate jwt, validate_options).to include(claims)
      end
    end

    context 'w HS256 keys' do
      let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
      let(:verifying_key) { signing_key }

      describe 'default alg' do
        let(:create_options) { {key: signing_key} }
        let(:validate_options) { {key: verifying_key} }
        it_behaves_like 'w #validate'
      end

      context "w 'alg' option" do
        describe 'HS256' do
          let(:create_options) { {alg: 'HS256', key: signing_key} }
          let(:validate_options) { {alg: 'HS256', key: verifying_key} }
          it_behaves_like 'w #validate'
        end

        describe "w alg 'none'" do
          let(:create_options) { {alg: 'none', key: signing_key} }
          let(:validate_options) { {alg: 'none', key: verifying_key} }
          it_behaves_like 'w #validate'
        end
      end
    end

    context 'w/o key' do
      context "w create alg 'none'" do
        let(:create_options) { {alg: 'none'} }
        describe "w validate alg 'none'" do
          let(:validate_options) { {alg: 'none'} }
          it_behaves_like 'w #validate'
        end

        describe "w default validate alg" do
          it 'raises' do
            jwt = JsonWebToken.create(claims, create_options)
            expect { JsonWebToken.validate(jwt) }
              .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
          end
        end
      end

      describe 'w default create alg' do
        it 'raises' do
          expect { JsonWebToken.create(claims) }.to raise_error(RuntimeError, 'Invalid key')
        end
      end
    end
  end
end
