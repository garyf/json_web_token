require 'json_web_token/util'

module JsonWebToken
  describe Util do
    describe '#constant_time_compare' do
      it 'guards against empty or nil strings' do
        expect(Util.constant_time_compare 'a', 'a').to be true

        expect(Util.constant_time_compare 'a', 'b').to be false
        expect(Util.constant_time_compare 'a', 'A').to be false
        expect(Util.constant_time_compare '', '').to be false
        expect(Util.constant_time_compare nil, nil).to be false
      end
    end

    describe '#symbolize_keys' do
      it 'returns a new hash with all keys converted to symbols' do
        original = {'a': 0, 'b': '2', c: '3'}
        expect(Util.symbolize_keys original).to include({a: 0, b: '2', c: '3'})
        expect(original).to eql original
      end
    end
  end
end
