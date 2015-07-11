require 'json_web_token/format/base64_url'

include JsonWebToken::Format::Base64Url

def plausible_message_signature?(str, bytesize = 32)
  parts = str.split('.')
  return false unless parts.length == 3
  mac = decode(parts[2])
  mac.bytesize == bytesize && mac.class == String
end

def plausible_unsecured_jws?(str)
  return false unless str.end_with?('.')
  str.split('.').length == 2
end
