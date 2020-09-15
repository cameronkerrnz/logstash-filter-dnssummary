# encoding: utf-8
require "logstash/filters/base"
require "public_suffix"
require "idna"

# This will need to be configured to suit the system you are
# deploying on. By default it will look for libidn.so, but
# on RHEL7 it only has libidn.so.11, and other systems may
# call this idn.so.11
#
# See https://www.rubydoc.info/gems/idna/0.1.0
#
Idna.configure do |config|
  config.ffi_lib = 'libidn.so.11'  # CentOS 7 and friends
end
Idna.reload!

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Dnssummary < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   dnssummary {
  #     source => "desthost"   # required
  #     target => "destsite"   # required
  #     include_ascii => false
  #     include_unicode => true
  #   }
  # }
  #
  config_name "dnssummary"

  # Replace the message with this value.
  config :source, :validate => :string, :required => true
  config :target, :validate => :string, :required => true
  config :include_unicode, :validate => :boolean, :default => true
  config :include_ascii, :validate => :boolean, :default => false
  # Hmmm, what to do with invalid types of input; currently we just copy them through
  # although potentially you might want something more nuanced.
  # The only thing we tag a failure for at present is when there is a IDNA security
  # error such as an embedded NUL byte.
  config :tag_on_failure, :validate => :string, :default => '_dnssummary_filter_error'

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    input = event.get(@source).strip
    domain = nil

    if PublicSuffix.valid?(input)
      begin
        domain = PublicSuffix.parse(input).domain

        if domain.nil?
          logger.warn("Parsed domain for #{input} returned a nil domain")
        end

      rescue PublicSuffix::DomainInvalid
        # eg. blah.localdomain
        # eg. -
        # eg. .
        domain = input
      rescue PublicSuffix::Error
        # don't log anything, but consider tagging
        domain = input
      rescue PublicSuffix::DomainNotAllowed
        # Eg. blogspot.com, which is the root of a private registry,
        # normally should be like something.blogspot.com
        domain = input
      end
    else
      # Domain is not valid by a rougher reckoning
      domain = input #'"valid?" returned false'
    end

    if domain.nil?
      logger.error("BUG: domain is still nil")
    end

    # Additionally, if we're aiming to group like with like,
    # we also should normalise case to lowercase and to
    # normalise the Unicode normal form to NFKC.
    #
    # NFKC is the correct normal form to use for things like
    # identifiers and database keys. This is taken care of
    # for us by the IDNA specification... mostly. It still
    # proves useful to explicitly downcase the ascii
    # version to cope with the likes of xn--Bcher-kva.example
    #
    domain_ascii = nil
    domain_unicode = nil
    begin
      domain_ascii = Idna.to_ascii(domain).downcase
      domain_unicode = Idna.to_unicode(domain_ascii)
    rescue SecurityError
      logger.warn("Input #{input.inspect} contains security errors and will not be parsed")
      event.tag(@tag_on_failure)
    end

    logger.warn("input is #{input.inspect}, domain is #{domain.inspect}, domain_ascii is #{domain_ascii.inspect}, domain_unicode is #{domain_unicode.inspect}")

    if @include_unicode and domain_unicode
      # Replace the event message with our message as configured in the
      # config file.
      event.set("[#{@target}][unicode]", domain_unicode)
    end

    if @include_ascii and domain_ascii
      event.set("[#{@target}][ascii]", domain_ascii)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Dnssummary
