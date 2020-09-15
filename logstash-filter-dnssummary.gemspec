Gem::Specification.new do |s|
  s.name          = 'logstash-filter-dnssummary'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'A logstash filter plugin for summarising DNS names'
  s.description   = 'Given a DNS name it can provide most significant useful part for identifying the site and normalising IDNA for presentation and security purposes.'
  s.homepage      = 'https://github.com/cameronkerrnz/logstash-filter-dnssummary'
  s.authors       = ['Cameron Kerr']
  s.email         = 'cameron.kerr.nz@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency 'public_suffix', '~> 4'
  s.add_runtime_dependency 'idna', '~> 0.1.0'   # requires libidn, but you need to specify the version (eg. 'libidn.so.11' in dnssummary.rb)
  s.add_development_dependency 'logstash-devutils'
end
