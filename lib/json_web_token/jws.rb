require 'json'
require 'json_web_token/format/base64_url'
require 'json_web_token/jwa'
require 'json_web_token/util'

module JsonWebToken
  module Jws

    MESSAGE_SIGNATURE_PARTS = 3

    module_function

    # http://tools.ietf.org/html/rfc7515#page-15
    def message_signature(header, payload, key)
      alg = alg_parameter(header)
      data = signing_input(header, payload)
      "#{data}.#{signature(alg, key, data)}"
    end

    # http://tools.ietf.org/html/rfc7515#page-16
    def validate(jws, algorithm, key = nil)
      compare_alg(jws, algorithm)
      return jws if algorithm == 'none'
      signature_valid?(jws, algorithm, key) ? jws : 'Invalid'
    end

    # http://tools.ietf.org/html/rfc7515#page-47
    def unsecured_jws(header, payload)
      fail("Invalid 'alg' header parameter") unless alg_parameter(header) == 'none'
      "#{signing_input(header, payload)}." # note trailing '.'
    end

    # private

    def alg_parameter(header)
      alg = Util.symbolize_keys(header)[:alg]
      alg && !alg.empty? ? alg : fail("Missing required 'alg' header parameter")
    end

    def signing_input(header, payload)
      "#{Format::Base64Url.encode header.to_json}.#{Format::Base64Url.encode payload}"
    end

    def signature(algorithm, key, data)
      Format::Base64Url.encode(Jwa.signed algorithm, key, data)
    end

    # http://tools.ietf.org/html/rfc7515#section-4.1.1
    def compare_alg(jws, algorithm)
      header = decoded_header_json_to_hash(jws)
      unless alg_parameter(header) == algorithm
        fail("Algorithm not matching 'alg' header parameter")
      end
    end

    def decoded_header_json_to_hash(jws)
      JSON.parse(Format::Base64Url.decode jws.split('.')[0])
    end

    def signature_valid?(jws, algorithm, key)
      ary = jws.split('.')
      return unless key && ary.length == MESSAGE_SIGNATURE_PARTS
      decoded_signature = Format::Base64Url.decode(ary[2])
      payload = "#{ary[0]}.#{ary[1]}"
      Jwa.verified?(decoded_signature, algorithm, key, payload)
    end

    private_class_method :alg_parameter,
      :signing_input,
      :signature,
      :compare_alg,
      :decoded_header_json_to_hash,
      :signature_valid?
  end
end
