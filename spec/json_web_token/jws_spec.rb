require 'json_web_token/jws'

module JsonWebToken
  describe Jws do
    context 'w payload' do
      let(:payload) { 'payload' }
      context '#message_signature' do
        shared_examples_for 'w #validate' do
          it 'verified' do
            jws = Jws.message_signature(header, payload, signing_key)
            expect(Jws.validate jws, algorithm, verifying_key).to eql jws
          end
        end

        context 'w HS256 keys' do
          let(:signing_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
          let(:verifying_key) { signing_key }
          context "w HS256 'alg' header parameter" do
            let(:header) { {alg: 'HS256'} }
            describe 'w passing a matching algorithm to #validate' do
              let(:algorithm) { 'HS256' }
              it_behaves_like 'w #validate'

              describe 'w/o passing key to #validate' do
                it "returns 'Invalid'" do
                  jws = Jws.message_signature(header, payload, signing_key)
                  expect(Jws.validate jws, algorithm, nil).to eql 'Invalid'
                end
              end
            end

            describe 'w/o passing a matching algorithm to #validate' do
              let(:algorithm) { 'RS256' }
              it 'raises' do
                jws = Jws.message_signature(header, payload, signing_key)
                expect { Jws.validate(jws, algorithm, verifying_key) }
                  .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
              end
            end
          end
        end
      end

      context 'header validation' do
        let(:signing_key) { 'signing_key' }
        describe "w/o a recognized 'alg' header parameter" do
          let(:header) { {alg: 'HS257'} }
          it 'raises' do
            expect { Jws.message_signature(header, payload, signing_key) }
              .to raise_error(RuntimeError, 'Unrecognized algorithm')
          end
        end

        describe "w/o a required 'alg' header parameter" do
          let(:header) { {typ: 'JWT'} }
          it 'raises' do
            expect { Jws.message_signature(header, payload, signing_key) }
              .to raise_error(RuntimeError, "Missing required 'alg' header parameter")
          end
        end
      end

      context '#unsecured_jws' do
        context 'w valid header' do
          let(:header) { {alg: 'none'} }
          describe 'w passing a matching algorithm to #validate' do
            let(:algorithm) { 'none' }
            it 'is verified' do
              jws = Jws.unsecured_jws(header, payload)
              expect(Jws.validate jws, algorithm).to eql jws
            end
          end

          describe 'w/o passing a matching algorithm to #validate' do
            let(:algorithm) { 'HS256' }
            let(:verifying_key) { 'gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C' }
            it 'raises' do
              jws = Jws.unsecured_jws(header, payload)
              expect { Jws.validate(jws, algorithm, verifying_key) }
                .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
            end
          end
        end

        describe 'w invalid header' do
          let(:header) { {alg: 'HS256'} }
          it 'raises' do
            expect { Jws.unsecured_jws(header, payload) }
              .to raise_error(RuntimeError, "Invalid 'alg' header parameter")
          end
        end
      end
    end
  end
end
