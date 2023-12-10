# encoding: utf-8

$:.unshift File.expand_path("../lib", __FILE__)
require "zwiebel/version"

Gem::Specification.new do |gem|
  gem.name = "zwiebel"
  gem.version = Zwiebel::VERSION
  gem.authors = ["Kurt Meyerhofer"]
  gem.homepage = "https://github.com/kmeyerhofer/zwiebel"
  gem.license = "LGPL-3.0-or-later"
  gem.summary = "Tor hidden service connector."
  gem.description = "zwiebel is a Tor network hidden service connector for version 3 .onion addresses."

  gem.files = Dir.glob("lib/**/*.rb")
  gem.platform = Gem::Platform::RUBY
  gem.require_paths = ["lib"]
  gem.requirements = ["Tor (>= 0.4.1.1-alpha)"]
  gem.add_runtime_dependency "base32", "~> 0.3"
  gem.add_development_dependency "rspec", "~> 3.12"
end
