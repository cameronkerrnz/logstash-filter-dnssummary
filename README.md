# DNS Summary ("Public Suffix") Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

The intent of this plugin is to take a FQDN, such as might be parsed from a Squid proxy access log, and summarise that to the 'site' domain; eg. anything.example.co.nz should summarise to example.co.nz. This is not a trivial process and for some inputs will require the use of the data from the [Public Suffix List](https://publicsuffix.org/), a snapshot of which is included locally. However, it doesn't stop there, and it will also attempt to provide sane (if inaccurate) summarisations for inputs such as IP addresses, and aims to do the correct thing for internationalised domain names.

This plugin is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Please submit any questions, bugs or issues about this plugin to the [issues page](https://github.com/cameronkerrnz/logstash-filter-dnssummary/issues)

For general Logstash questions, try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### (Optional, but Highly Recommended) Use Dev Containers

If you want to have a repeatable development environment that doesn't pollute the rest of your environment with build dependencies and idiosyncrasies of developing Logstash plugins, then you might like to consider using Dev Containers, which this repository has been set up to use.

This repository is using the [cameronkerrnz/logstash-plugin-dev](https://code.visualstudio.com/docs/remote/containers) container image, which you can see referenced in .devcontainer/Dockerfile

When you've launched this project inside the dev container, you should just need to:

```sh
bundle install
bundle exec rspec
gem build logstash-filter-dnssummary.gemspec
```

### Coding

- To get started, you'll need JRuby with the Bundler gem installed. This is already done for you if you are using the dev container.

- Install dependencies
```sh
bundle install
```

### Unit Tests

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### Integration Tests

This repository contains a supplementary Docker image specification in the file Dockerfile.qa.
This image will inherit off the official Logstash OSS Docker image, and install your plugin,
and a test harness and input data-set.
The primary purpose of this QA build is to harvest performance timings.
From outside the dev container (if you are using that), you can run this as follows:

```sh
docker build -t logstash-filter-dnssummary:qa -f Dockerfile.qa .
docker run --rm -it logstash-filter-dnssummary:qa
```

If you need further debug logging, you might use instead:

```sh
docker run --rm -it logstash-filter-dnssummary.qa --log.level=debug
```

### Run in an installed Logstash

- Build your plugin gem
```sh
gem build logstash-filter-dnssummary.gemspec
```
- Install the plugin from the Logstash home
```sh
bin/logstash-plugin install /your/local/plugin/logstash-filter-dnssummary.gem
```
- Start Logstash and proceed to test the plugin. An example configuration can be found in [qa/pipeline/logstash.conf](qa/pipeline/logstash.conf)

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.
