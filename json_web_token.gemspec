# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require 'json_web_token/version'

Gem::Specification.new do |s|
  s.author = 'Gary Fleshman'
  s.email = 'gf4cl@verizon.net'
  s.files = `git ls-files`.split("\n")
  s.homepage = 'https://github.com/garyf/json_web_token'
  s.name = 'json_web_token'
  s.platform = Gem::Platform::RUBY
  s.summary = 'JSON Web Token for Ruby'
  s.version = JsonWebToken::VERSION
  # recommended
  s.license = 'MIT'
  # optional
  s.add_runtime_dependency 'json', '~> 1.8', '>= 1.8.3'
  s.add_development_dependency 'pry-byebug', '~> 3.1'
  s.add_development_dependency 'rspec', '~> 3.3'
  s.description = 'Ruby implementation of the JSON Web Token Standard Track RFC 4627'
end
