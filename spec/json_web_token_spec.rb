require 'json_web_token'

describe JsonWebToken do
  context '#sign' do
    let(:claims) { { iss: 'joe', exp: 1300819380, :'http://example.com/is_root' => true} }
    shared_examples_for 'w #verify' do
      it 'w a claims set' do
        jwt = JsonWebToken.sign(claims, sign_options)
        expect(JsonWebToken.verify(jwt, verify_options)[:ok]).to include(claims)
      end
    end

    context 'w HS256 keys' do
      let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
      let(:verifying_key) { signing_key }

      describe 'default alg' do
        let(:sign_options) { {key: signing_key} }
        let(:verify_options) { {key: verifying_key} }
        it_behaves_like 'w #verify'
      end

      context "w 'alg' option" do
        describe 'HS256' do
          let(:sign_options) { {alg: 'HS256', key: signing_key} }
          let(:verify_options) { {alg: 'HS256', key: verifying_key} }
          it_behaves_like 'w #verify'
        end

        describe "w alg 'none'" do
          let(:sign_options) { {alg: 'none', key: signing_key} }
          let(:verify_options) { {alg: 'none', key: verifying_key} }
          it_behaves_like 'w #verify'
        end
      end
    end
  end

  context 'module alias JWT' do
    describe '#sign' do
      let(:claims) { { iss: 'joe', exp: 1300819380, :'http://example.com/is_root' => true} }
      it 'recognized' do
        expect(JsonWebToken.sign(claims, key: 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C')).to be
      end
    end
  end
end
