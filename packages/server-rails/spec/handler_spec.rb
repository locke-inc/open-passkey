# frozen_string_literal: true

require "spec_helper"

RSpec.describe OpenPasskey::PasskeyHandler do
  let(:config) do
    c = OpenPasskey::Config.new
    c.rp_id = "example.com"
    c.rp_display_name = "Example"
    c.origin = "https://example.com"
    c
  end

  let(:handler) { OpenPasskey::PasskeyHandler.new(config) }

  describe "#begin_registration" do
    it "returns valid options" do
      options = handler.begin_registration("user1", "alice")

      expect(options[:challenge]).not_to be_nil
      expect(options[:rp][:id]).to eq("example.com")
      expect(options[:rp][:name]).to eq("Example")
      expect(options[:user][:name]).to eq("alice")
      expect(options[:pubKeyCredParams].length).to eq(3)
      expect(options[:pubKeyCredParams][0][:alg]).to eq(-52)
      expect(options[:pubKeyCredParams][2][:alg]).to eq(-7)
    end

    it "raises on empty userId" do
      expect { handler.begin_registration("", "alice") }.to raise_error(OpenPasskey::PasskeyError)
    end

    it "raises on empty username" do
      expect { handler.begin_registration("user1", "") }.to raise_error(OpenPasskey::PasskeyError)
    end
  end

  describe "#begin_authentication" do
    it "returns valid options" do
      options = handler.begin_authentication("user1")

      expect(options[:challenge]).not_to be_nil
      expect(options[:rpId]).to eq("example.com")
      expect(options[:userVerification]).to eq("preferred")
    end

    it "works with empty userId for discoverable" do
      options = handler.begin_authentication("")
      expect(options[:challenge]).not_to be_nil
      expect(options).not_to have_key(:allowCredentials)
    end
  end
end
