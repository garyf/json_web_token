require 'json_web_token/format/base64_url'

include JsonWebToken::Format::Base64Url

def plausible_message_signature?(str)
  parts = str.split('.')
  return false unless parts.length == 3
  mac = decode(parts[2])
  mac.bytesize == 32 && mac.class == String
end

def plausible_unsecured_jws?(str)
  return false unless str.end_with?('.')
  str.split('.').length == 2
end
