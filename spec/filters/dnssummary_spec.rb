# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/dnssummary"

describe LogStash::Filters::Dnssummary do
  describe "Defaults" do
    let(:config) do <<-CONFIG
      filter {
        dnssummary {
          source => "desthost"
          target => "destsite"
        }
      }
    CONFIG
    end

    sample("desthost" => "something.example.ac.nz") do
      expect(subject).to include("destsite")
      expect(subject).get('destsite').to include('display')
      expect(subject).get('destsite').not_to include('identifier')
      expect(subject.get('destsite').get('display')).to eq('example.ac.nz')
    end
  end
end
