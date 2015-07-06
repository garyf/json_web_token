module JsonWebToken
  module Jwt

    ALGORITHM_DEFAULT = 'HS256'
    HEADER_DEFAULT = {
      typ: 'JWT',
      alg: ALGORITHM_DEFAULT
    }

    module_function

    def config_header(options)
      HEADER_DEFAULT.merge(alg_parameter_required options)
    end

    # private

    def alg_parameter_required(options)
      hsh = options.select { |k, _v| k == :alg } # filter unsupported keys
      alg = hsh[:alg]
      alg && !alg.empty? ? hsh : {}
    end

    private_class_method :alg_parameter_required
  end
end
