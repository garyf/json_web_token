require 'openssl'

module EcdsaKey

  BUILT_IN_CURVES = {
    '256' => 'prime256v1',
    '384' => 'secp384r1',
    '512' => 'secp521r1'
  }

  module_function

  def curve_new(sha_bits)
    OpenSSL::PKey::EC.new(BUILT_IN_CURVES[sha_bits])
  end

  def public_key_str(curve, base = 16)
    curve.generate_key unless curve.private_key
    curve.public_key.to_bn.to_s(base)
  end

  def public_key_new(sha_bits, public_key_str, base = 16)
    curve_name = BUILT_IN_CURVES[sha_bits]
    fail('Unsupported curve') unless curve_name
    group = OpenSSL::PKey::EC::Group.new(curve_name)
    curve = OpenSSL::PKey::EC.new(group)
    curve.public_key = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(public_key_str, base))
    curve
  end
end
