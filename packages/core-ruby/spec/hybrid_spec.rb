# frozen_string_literal: true

require "json"
require "spec_helper"

RSpec.describe "Hybrid authentication vectors" do
  vectors_path = File.expand_path("../../../spec/vectors/hybrid_authentication.json", __dir__)
  data = JSON.parse(File.read(vectors_path))

  data["vectors"].each do |vector|
    it vector["name"] do
      run_authentication_vector(vector)
    end
  end

  def run_authentication_vector(vector)
    input = vector["input"]
    credential = input["credential"]
    response = credential["response"]
    expected = vector["expected"]

    stored_public_key_cose = OpenPasskey::Base64Url.decode(input["storedPublicKeyCose"])

    if expected["success"]
      result = OpenPasskey::WebAuthn.verify_authentication(
        rp_id: input["rpId"],
        expected_challenge: input["expectedChallenge"],
        expected_origin: input["expectedOrigin"],
        stored_public_key_cose: stored_public_key_cose,
        stored_sign_count: input["storedSignCount"].to_i,
        client_data_json: response["clientDataJSON"],
        authenticator_data: response["authenticatorData"],
        signature: response["signature"]
      )

      if expected["signCount"]
        expect(result.sign_count).to eq(expected["signCount"])
      end
    else
      expect {
        OpenPasskey::WebAuthn.verify_authentication(
          rp_id: input["rpId"],
          expected_challenge: input["expectedChallenge"],
          expected_origin: input["expectedOrigin"],
          stored_public_key_cose: stored_public_key_cose,
          stored_sign_count: input["storedSignCount"].to_i,
          client_data_json: response["clientDataJSON"],
          authenticator_data: response["authenticatorData"],
          signature: response["signature"]
        )
      }.to raise_error(OpenPasskey::WebAuthnError) { |e|
        expect(e.code).to eq(expected["error"])
      }
    end
  end
end
