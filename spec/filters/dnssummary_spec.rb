# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/dnssummary"

describe LogStash::Filters::Dnssummary do
  describe "With basic settings" do
    let(:config) do <<-CONFIG
      filter {
        dnssummary {
          source => "in_field"
          target => "out_field"
        }
      }
    CONFIG
    end

    context "basic expectations" do
      sample("in_field" => "something.example.ac.nz") do
        expect(subject).to include("out_field")
        expect(subject.get('out_field')).to include('unicode')
        expect(subject.get('out_field')).not_to include('ascii')
        expect(subject.get('[out_field][unicode]')).to eq('example.ac.nz')
      end
      sample("in_field" => "something.example.ac.nz.") do
        expect(subject.get('[out_field][unicode]')).to eq('example.ac.nz')
      end
      sample("in_field" => "3.1o19sr00s2s17s4qp3759pn9ro30n2n4n941on29s3s35qppp742380s6487np3.poqp0r741pn37393648s20n65203rn4o44387s5831o276q6s5rqsr16n809qp4.86752ss34q9sns005o.35n2s0s521p9rn7o75q0r479rpqq7o0oq6r6o20p.i.01.mac.sophosxl.net") do
        expect(subject.get('[out_field][unicode]')).to eq('sophosxl.net')
      end
    end

    context "invalid public suffixes" do
      sample("in_field" => "x.yz") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("x.yz")
      end
    end

    context "private registries" do
      sample("in_field" => "something.blogspot.com") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("something.blogspot.com")
        # because its a private registry; people can register a name under blogspot.com
      end
      sample("in_field" => "blogspot.com") do
        # PublicSuffix::DomainNotAllowed
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("blogspot.com")
      end
    end

    context "basic IDNA" do
      sample("in_field" => "高兴.学上.中国") do
        expect(subject.get('[out_field][unicode]')).to eq("学上.中国")
      end
      sample("in_field" => "bücher.example") do
        expect(subject.get('[out_field][unicode]')).to eq("bücher.example")
      end
      sample("in_field" => "xn--bcher-kva.example") do
        expect(subject.get('[out_field][unicode]')).to eq("bücher.example")
      end
    end

    context "invalid inputs should result in identity" do
      sample("in_field" => "") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("")
      end
      sample("in_field" => "-") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("-")
      end
      sample("in_field" => ".") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq(".")
      end
      sample("in_field" => "foo.") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("foo.")  #absolute
      end
      sample("in_field" => "foo") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("foo")  #relative to user's search path
      end
      sample("in_field" => "https://www.google.com/") do
        expect(subject.get('[out_field][unicode]')).to eq("https://www.google.com/")
      end
    end

    context "data cleanup" do
      sample("in_field" => " space.example.ac.nz ") do
        expect(subject.get('[out_field][unicode]')).to eq("example.ac.nz")
      end
      sample("in_field" => "\ttab.example.ac.nz\t") do
        expect(subject.get('[out_field][unicode]')).to eq("example.ac.nz")
      end
      sample("in_field" => "\rcr.example.ac.nz\r") do
        expect(subject.get('[out_field][unicode]')).to eq("example.ac.nz")
      end
      sample("in_field" => "\nlf.example.ac.nz\n") do
        expect(subject.get('[out_field][unicode]')).to eq("example.ac.nz")
      end
      sample("in_field" => "something.example.ac.nz") do
        expect(subject.get('[out_field][unicode]')).to eq('example.ac.nz')
      end
      sample("in_field" => "something.example.com\0.boo.com") do
        # The NUL in this position will be treated by public_suffix
        # But is likely bad enough that we should fail it.
        expect(subject.get('[out_field][unicode]')).to eq("boo.com")
      end
      sample("in_field" => "something.example.com.boo\0.com") do
        # The NUL in this position will be treated by libidn, which is C
        # but should result in a SecurityError
        expect(subject).not_to include('out_field')
        expect(subject.get('tags')).to include('_dnssummary_filter_error')
      end
    end
  end

  describe "Both Unicode and ASCII" do
    let(:config) do <<-CONFIG
      filter {
        dnssummary {
          source => "in_field"
          target => "out_field"
          include_ascii => true
          include_unicode => true
        }
      }
    CONFIG
    end

    context "case-folding with IDNA" do
      sample("in_field" => "Bücher.example") do
        expect(subject.get('[out_field][unicode]')).to eq("bücher.example")
        expect(subject.get('[out_field][ascii]')).to eq("xn--bcher-kva.example")
      end
      sample("in_field" => "xn--Bcher-kva.example") do
        expect(subject.get('[out_field][unicode]')).to eq("bücher.example")
        expect(subject.get('[out_field][ascii]')).to eq("xn--bcher-kva.example")
      end
    end

    context "visual confusables" do
      # These are not what they appear; the vowels and the p are different code-points
      sample("in_field" => "wіkіреdіа.org") do
        expect(subject.get('[out_field][unicode]')).to eq("wіkіреdіа.org")
        expect(subject.get('[out_field][ascii]')).to eq("xn--wkd-8cdx9d7hbd.org")
      end
    end

    context "supposedly illegal in IDNA2008" do
      # RFC5891 Appendix A: Disallow symbol and punc chars except where special exceptions are necessary
      # libidn is based on IDNA2003 (https://www.gnu.org/software/libidn/), and we should really be
      # using libidn2. For RHEL7, this is available via EPEL.
      #
      sample("in_field" => "i❤.ws") do
        expect(subject.get('[out_field][unicode]')).to eq("i❤.ws")
        expect(subject.get('[out_field][ascii]')).to eq("xn--i-7iq.ws")
      end
      sample("in_field" => "👁️👄👁️.fm") do
        # See https://en.wikipedia.org/wiki/Emoji_domain
        expect(subject.get('[out_field][unicode]')).to eq("👁👄👁.fm")   # NFKC effect
        expect(subject.get('[out_field][ascii]')).to eq("xn--mp8hai.fm")
      end
      sample("in_field" => "😉.👁️👄👁️.fm") do
        # See https://en.wikipedia.org/wiki/Emoji_domain
        expect(subject.get('[out_field][unicode]')).to eq("👁👄👁.fm")
        expect(subject.get('[out_field][ascii]')).to eq("xn--mp8hai.fm")
      end
      sample("in_field" => "xn--n28h.xn--mp8hai.fm") do
        # See https://en.wikipedia.org/wiki/Emoji_domain
        expect(subject.get('[out_field][unicode]')).to eq("👁👄👁.fm")
        expect(subject.get('[out_field][ascii]')).to eq("xn--mp8hai.fm")
      end
    end

    context "IP addresses" do
      sample("in_field" => "172.16.30.40") do
        expect(subject.get('[out_field][unicode]')).to eq("172.16.0.0/12")
      end
      sample("in_field" => "127.0.0.1") do
        expect(subject.get('[out_field][unicode]')).to eq("127.0.0.1")
      end
      sample("in_field" => "192.168.0.1.") do
        # Ideally would fall out as an identity transformation, but it doesn't
        # parse as an IP address and so public_suffix gets its hands on it.
        # Happy to treat this an undefined behaviour for now.
        # This unit-test is just to alert for changing behaviour.
        expect(subject.get('[out_field][unicode]')).to eq("0.1")
      end
      sample("in_field" => "1.1.168.192.in-addr.arpa") do
        # When might we see this, I can't think of a single time I've seen this
        # in something not a debug log.
        # Considered as undefined behaviour; this unit test is just
        # to alert for changing behaviour
        expect(subject.get('[out_field][unicode]')).to eq("192.in-addr.arpa")
      end
      sample("in_field" => "0000:0000:0000:0000:0000:0000:0000:0001") do
        expect(subject.get('[out_field][unicode]')).to eq("::1")
      end
      sample("in_field" => "::1") do
        expect(subject.get('[out_field][unicode]')).to eq("::1")
      end
      sample("in_field" => "fe80::109a:804f:2d0f:5a24%56") do
        # IPAddr doesn't like IPv6 interface identifier, although
        # you're very unlikely to see an interface identifier in a
        # context where you'd want to use this module, so in this
        # case I'd be happy enough with an identity.
        expect(subject.get('[out_field][unicode]')).to eq("fe80::109a:804f:2d0f:5a24%56")
      end
      sample("in_field" => "fe80::109a:804f:2d0f:5a24") do
        # Could consider using compression (::) as a natural place to break
        expect(subject.get('[out_field][unicode]')).to eq("fe80::/48")
      end
      sample("in_field" => "2407:7000:8246:1800:22b0:1ff:fec4:9ba4") do
        expect(subject.get('[out_field][unicode]')).to eq("2407:7000:8246::/48")
      end
      sample("in_field" => "[2407:7000:8246:1800:22b0:1ff:fec4:9ba4]") do
        # This is what you might see as the host part of a URI
        expect(subject.get('[out_field][unicode]')).to eq("2407:7000:8246::/48")
      end
    end
  end

  describe "With settings for QA" do
    let(:config) do <<-CONFIG
      filter {
        dnssummary {
          id => "sut"
          add_field => {
            "somekey" => "someval"
          }
          source => "in_field"
          target => "out_field"
          include_unicode => true
          include_ascii => true
        }
      }
    CONFIG
    end

    sample("in_field" => "example.com") do
      expect(subject).to include('somekey')
    end
  end
end
