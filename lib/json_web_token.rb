require 'json_web_token/jwt'

module JsonWebToken

  module_function

  def create(claims, options = {})
    Jwt.create(claims, options)
  end

  def validate(jwt, options = {})
    Jwt.validate(jwt, options)
  end
end
