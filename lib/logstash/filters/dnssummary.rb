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

  private
  def natural_mask_addr(ipaddr)
    # We might be able to do a better job here if we had the input string too,
    # to find where :: appears (if it appears).
    # Cobbled together from https://ruby-doc.org/stdlib-2.5.1/libdoc/ipaddr/rdoc/IPAddr.html
    ipaddr = ipaddr.native
    if ipaddr.ipv4?
      if ipaddr & 0xff000000 == 0x0a000000     # 10.0.0.0/8
        return 8
      elsif ipaddr & 0xfff00000 == 0xac100000  # 172.16.0.0/12
        return 12
      elsif ipaddr & 0xffff0000 == 0xc0a80000  # 192.168.0.0/16
        return 16
      elsif ipaddr & 0xffff0000 == 0xa9fe0000  # 169.254.0.0/16
        return 16
      elsif ipaddr == 0x7F000001
        return 32
      else
        return 28  # Debatable; probably room for configuration here
      end
    elsif ipaddr.ipv6?
      # A lot more _could_ be done here with regard to different
      # IPv6 address ranges (eg. 6-to-4, Toredo, Link local, Site local, etc.)
      if ipaddr == 0x0000_0000_0000_0000_0000_0000_0000_0001
        return 128
      else
        return 48
        # Ref: https://www.apnic.net/community/policy/ipv6-address-policy_obsolete/#5.5
        # ISPs (LIRs) should give an end-user a /48 or a /64 at smallest
      end
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end # def natural_mask_addr

  private
  def summarised_ip(maybe_ip)
    begin
      ip = IPAddr.new(maybe_ip)
      prefix_len = natural_mask_addr(ip)
      if ( ip.ipv4? && prefix_len == 32 ) || ( ip.ipv6? && prefix_len == 128 )
        summarised_ip = "#{ip.mask(prefix_len).to_s}"
      else
        summarised_ip = "#{ip.mask(prefix_len).to_s}/#{prefix_len}"
      end
      logger.warn("Determined prefix length of #{prefix_len} to be suitable for #{maybe_ip}, parsed as #{ip}, and returned #{summarised_ip}")
      return summarised_ip

    rescue IPAddr::InvalidAddressError
      return nil
    end
  end # def summarised_ip

  public
  def filter(event)

    input = event.get(@source).strip

    domain = nil
    domain_ascii = nil
    domain_unicode = nil

    # https://github.com/weppos/publicsuffix-ruby/issues/126
    # IPv4 addresses share the same basic syntax as FQDNs, and
    # public_suffix returns 0.1 for an input of 192.168.0.1
    #
    # IPv6 are not an issue, and similarly URLs are not either.
    #
    # Given that you could reasonably expect to see an IPv4
    # address in a place where you might also expect a FQDN,
    # we better do something about it.
    #
    summarised_ip = summarised_ip(input)

    if summarised_ip

      domain_ascii = summarised_ip
      domain_unicode = summarised_ip

    elsif PublicSuffix.valid?(input) 
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
      begin
        domain_ascii = Idna.to_ascii(domain).downcase
        domain_unicode = Idna.to_unicode(domain_ascii)
      rescue SecurityError
        logger.warn("Input #{input.inspect} contains security errors and will not be parsed")
        event.tag(@tag_on_failure)
      end

    else
      # An invalid sort of input, fallback to an identity tranformation so the user
      # still has a shot of getting useful aggregations.
      #
      # Debatable; maybe we should allow this is to be configured as something to
      # flag an error or to replace with some sort of replacable marker.

      domain_unicode = input
      domain_ascii = input
    end

    logger.info("input is #{input.inspect}, domain is #{domain.inspect}, domain_ascii is #{domain_ascii.inspect}, domain_unicode is #{domain_unicode.inspect}")

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
