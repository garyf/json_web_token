require 'json_web_token/util'

module JsonWebToken
  describe Util do
    describe '#symbolize_keys' do
      it 'returns a new hash with all keys converted to symbols' do
        original = {'a': 0, 'b': '2', c: '3'}
        expect(Util.symbolize_keys original).to include({a: 0, b: '2', c: '3'})
        expect(original).to eql original
      end
    end
  end
end
