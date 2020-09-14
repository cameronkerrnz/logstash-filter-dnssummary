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
      sample("in_field" => "-") do
        expect(subject).to include("out_field")
        expect(subject.get('[out_field][unicode]')).to eq("-")
      end
    end

    # Things that could be better
    # 1.1.168.192.in-addr.arpa.   currently return 192.in-addr.arpa

  end

  describe "Looking more at IDNA" do
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
    end
  end
end
