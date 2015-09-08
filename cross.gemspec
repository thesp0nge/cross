# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cross/version'


Gem::Specification.new do |gem|
  gem.authors       = ["Paolo Perego"]
  gem.email         = ["paolo@codiceinsicuro.it"]
  gem.description   = %q{cross is a tool designed to autmate cross site scripting testing. Cross is able to crawl a web application, find forms and injection point and exploit them with a large number of payloads. Of course, it works best to spot reflected XSS.}
  gem.summary       = %q{cross is an automated cross site scripting testing tool}
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

end
