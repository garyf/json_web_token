require 'json_web_token/jwa'

module JsonWebToken
  describe Jwa do
    context 'detect changed signature or data' do
      let(:valid_data) { 'valid.data' }
      let(:other_data) { 'other.data' }

      shared_examples_for '#signed' do
        it 'and #verified?' do
          signature = Jwa.signed(algorithm, private_key, valid_data)
          a_signature = Jwa.signed(algorithm, private_key, other_data)

          expect(Jwa.verified? signature, algorithm, private_key, valid_data).to be true
          expect(Jwa.verified? signature, algorithm, private_key, other_data).to be false
          expect(Jwa.verified? a_signature, algorithm, private_key, valid_data).to be false
        end
      end

      describe 'w/o key' do
        let(:algorithm) { 'HS256' }
        it 'raises' do
          expect { Jwa.signed(algorithm, nil, valid_data) }
            .to raise_error(RuntimeError, 'Invalid key')
        end
      end

      shared_examples_for 'unrecognized' do
        it 'raises' do
          expect { Jwa.signed(algorithm, private_key, valid_data) }
            .to raise_error(RuntimeError, 'Unrecognized algorithm')
        end
      end

      describe 'HS256' do
        let(:private_key) { 'this_a_32_character_private_key!' }
        let(:algorithm) { 'HS256' }
        it_behaves_like '#signed'
      end

      describe 'invalid algorithm' do
        let(:private_key) { 'secret' }
        ['HT256', 'HS257', '', nil].each do |elt|
          let(:algorithm) { "#{elt}" }
          it_behaves_like 'unrecognized'
        end
      end
    end
  end
end
