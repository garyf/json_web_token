require 'json_web_token/jwt'

module JsonWebToken

  module_function

  def create(claims, options = {})
    Jwt.sign(claims, options)
  end

  def validate(jwt, options = {})
    Jwt.verify(jwt, options)
  end
end
