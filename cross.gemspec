# -*- encoding: utf-8 -*-
require File.expand_path('../lib/cross/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Paolo Perego"]
  gem.email         = ["thesp0nge@gmail.com"]
  gem.description   = %q{cross is a cross site scripting testing tool}
  gem.summary       = %q{cross is a cross site scripting testing tool}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "cross"
  gem.require_paths = ["lib"]
  gem.version       = Cross::VERSION


  gem.add_development_dependency "rake"
  gem.add_development_dependency "rspec"
  gem.add_dependency "rest-open-uri"
  gem.add_dependency "mechanize"
  gem.add_dependency "logger"
  gem.add_dependency "rainbow"

  gem.add_dependency "codesake-commons", ">= 0.89.0"
end
