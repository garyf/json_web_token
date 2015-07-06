require 'json_web_token/jws'

module JsonWebToken
  describe Jws do
    context '#message_signature' do
      let(:key) { 'this_a_32_character_private_key!' }
      let(:payload) { 'payload' }

      shared_examples_for 'w #validate' do
        it 'verified' do
          serialized_output = Jws.message_signature(header, payload, key)
          expect(Jws.validate serialized_output, algorithm, key).to eql serialized_output
        end
      end

      context 'w HS256' do
        let(:algorithm) { 'HS256' }

        context "w matching 'alg' header parameter" do
          let(:header) { {alg: 'HS256'} }
          it_behaves_like 'w #validate'

          describe 'w/o passing key to #validate' do
            it 'invalid' do
              serialized_output = Jws.message_signature(header, payload, key)
              expect(Jws.validate serialized_output, algorithm, nil).to eql 'Invalid'
            end
          end
        end

        describe "w/o an implemented 'alg' header parameter" do
          let(:header) { {alg: 'other'} }
          it 'raises' do
            expect { Jws.message_signature(header, payload, key) }
              .to raise_error(RuntimeError, 'Unrecognized algorithm')
          end
        end

        describe "w/o required 'alg' header parameter" do
          let(:header) { {typ: 'JWT'} }
          it 'raises' do
            expect { Jws.message_signature(header, payload, key) }
              .to raise_error(RuntimeError, "Missing required 'alg' header parameter")
          end
        end

        describe '#validate w/o a matching algorithm' do
          let(:header) { {alg: 'HS256'} }
          it 'raises' do
            serialized_output = Jws.message_signature(header, payload, key)
            expect { Jws.validate(serialized_output, 'none', key) }
              .to raise_error(RuntimeError, "Algorithm not matching 'alg' header parameter")
          end
        end
      end
    end

    context '#unsecured_jws' do
      let(:payload) { 'payload' }
      describe 'w matching algorithm' do
        let(:header) { {alg: 'none'} }
        it 'verified' do
          serialized_output = Jws.unsecured_jws(header, payload)
          expect(Jws.validate serialized_output, 'none').to eql serialized_output
        end
      end

      describe 'w/o matching algorithm' do
        let(:header) { {alg: 'HS256'} }
        it 'raises' do
          expect { Jws.unsecured_jws(header, payload) }
            .to raise_error(RuntimeError, "Invalid 'alg' header parameter")
        end
      end
    end
  end
end
