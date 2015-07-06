require 'json_web_token/format/base64_url'

module JsonWebToken
  module Format
    describe Base64Url do
      context '#encode' do
        shared_examples_for 'w #decode' do
          it 'matches' do
            encoded = Base64Url.encode(str)
            expect(Base64Url.decode encoded).to eql str
          end
        end

        describe 'typical' do
          let(:str) { '{"typ":"JWT", "alg":"HS256"}' }
          it_behaves_like 'w #decode'
        end

        describe 'w whitespace' do
          let(:str) { '{"typ" :"JWT" ,  "alg" :"HS256"   }' }
          it_behaves_like 'w #decode'
        end

        describe 'w line feed and carriage return' do
          let(:str) { '{"typ":"JWT",/n "a/rlg":"HS256"}' }
          it_behaves_like 'w #decode'
        end

        shared_examples_for 'given encoding' do
          it 'matches' do
            expect(Base64Url.encode str).to eql encoded
            expect(Base64Url.decode encoded).to eql str
          end
        end

        describe 'w no padding char' do
          let(:str) { '{"typ":"JWT", "alg":"none"}' }
          let(:encoded) { 'eyJ0eXAiOiJKV1QiLCAiYWxnIjoibm9uZSJ9'}
          it_behaves_like 'given encoding'
        end

        context 'w 1 padding char' do
          let(:str) { '{"typ":"JWT", "alg":"algorithm"}' }

          describe 'present' do
            let(:encoded) { 'eyJ0eXAiOiJKV1QiLCAiYWxnIjoiYWxnb3JpdGhtIn0='}
            it 'matches' do
              expect(Base64Url.decode encoded).to eql str
            end
          end

          describe 'removed' do
            let(:encoded) { 'eyJ0eXAiOiJKV1QiLCAiYWxnIjoiYWxnb3JpdGhtIn0'}
            it_behaves_like 'given encoding'
          end
        end

        context 'w 2 padding char' do
          let(:str) { '{"typ":"JWT", "alg":"HS256"}' }

          describe 'present' do
            let(:encoded) { 'eyJ0eXAiOiJKV1QiLCAiYWxnIjoiSFMyNTYifQ=='}
            it 'matches' do
              expect(Base64Url.decode encoded).to eql str
            end
          end

          describe 'removed' do
            let(:encoded) { 'eyJ0eXAiOiJKV1QiLCAiYWxnIjoiSFMyNTYifQ'}
            it_behaves_like 'given encoding'
          end
        end

        describe 'invalid encoding' do
          let(:encoded) { 'InR5cCI6IkpXVCIsICJhbGciOiJub25lI'}
          it 'raises' do
            expect { Base64Url.decode(encoded) }
              .to raise_error(RuntimeError, 'Invalid base64 string')
          end
        end
      end
    end
  end
end
