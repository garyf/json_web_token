# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'json_web_token/version'

Gem::Specification.new do |s|
  s.name          = 'json_web_token'
  s.version       = JsonWebToken::VERSION
  s.authors       = ['Gary Fleshman']
  s.email         = ['gfleshman@newforge-tech.com']

  s.summary       = 'JSON Web Token (JWT) for Ruby'
  s.description   = 'Ruby implementation of the JSON Web Token (JWT) standard, RFC 7519'
  s.homepage      = 'https://github.com/garyf/json_web_token'
  s.license       = 'MIT'

  s.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end

  s.require_paths = ['lib']

  s.platform = Gem::Platform::RUBY
  s.required_ruby_version = '>= 2.2.0'

  s.add_runtime_dependency 'json', '~> 2.1'

  s.add_development_dependency 'bundler', '~> 1.15'
  s.add_development_dependency 'rake', '~> 12.0'
  s.add_development_dependency 'rspec', '~> 3.6'
  s.add_development_dependency 'pry-byebug', '~> 3.4'
  s.add_development_dependency 'simplecov', '~> 0.14'
  s.add_development_dependency 'yard', '~> 0.9'
  s.add_development_dependency 'wwtd', '~> 1.3'
end
