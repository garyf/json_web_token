require 'json_web_token/jws'

module JsonWebToken
  module Jwt

    ALGORITHM_DEFAULT = 'HS256'
    HEADER_DEFAULT = {
      typ: 'JWT',
      alg: ALGORITHM_DEFAULT
    }

    module_function

    # http://tools.ietf.org/html/rfc7519#page-12
    def create(claims, options = {})
      message = validated_message(claims)
      key = options[:key]
      header = config_header(options)
      return Jws.unsecured_jws(header, message) if header[:alg] == 'none'
      Jws.message_signature(header, message, key)
    end

    def validate(jwt, options = {})
      alg = options[:alg] || ALGORITHM_DEFAULT
      jws = Jws.validate(jwt, alg, options[:key])
      jws == 'Invalid' ? jws : Util.symbolize_keys(decoded_message_json_to_hash jws)
    end

    # private

    def validated_message(claims)
      fail('Claims not provided') if !claims || claims.empty?
      claims.to_json
    end

    def config_header(options)
      HEADER_DEFAULT.merge(alg_parameter_required options)
    end

    def alg_parameter_required(options)
      hsh = options.select { |k, _v| k == :alg } # filter unsupported keys
      alg = hsh[:alg]
      alg && !alg.empty? ? hsh : {}
    end

    def decoded_message_json_to_hash(jws)
      ary = jws.split('.')
      return jws unless ary.length > 1 # invalid
      JSON.parse(Format::Base64Url.decode ary[1])
    end

    private_class_method :validated_message,
      :config_header,
      :alg_parameter_required,
      :decoded_message_json_to_hash
  end
end
