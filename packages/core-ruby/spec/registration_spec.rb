# frozen_string_literal: true

require "json"
require "spec_helper"

RSpec.describe "Registration vectors" do
  vectors_path = File.expand_path("../../../spec/vectors/registration.json", __dir__)
  data = JSON.parse(File.read(vectors_path))

  data["vectors"].each do |vector|
    it vector["name"] do
      input = vector["input"]
      credential = input["credential"]
      response = credential["response"]
      expected = vector["expected"]

      if expected["success"]
        result = OpenPasskey::WebAuthn.verify_registration(
          rp_id: input["rpId"],
          expected_challenge: input["expectedChallenge"],
          expected_origin: input["expectedOrigin"],
          client_data_json: response["clientDataJSON"],
          attestation_object: response["attestationObject"]
        )

        if expected["credentialId"]
          expect(result.credential_id).to eq(expected["credentialId"])
        end
        if expected["publicKeyCose"]
          expect(result.public_key_cose).to eq(expected["publicKeyCose"])
        end
        if expected["signCount"]
          expect(result.sign_count).to eq(expected["signCount"])
        end
        if expected["rpIdHash"]
          expect(result.rp_id_hash).to eq(expected["rpIdHash"])
        end
      else
        expect {
          OpenPasskey::WebAuthn.verify_registration(
            rp_id: input["rpId"],
            expected_challenge: input["expectedChallenge"],
            expected_origin: input["expectedOrigin"],
            client_data_json: response["clientDataJSON"],
            attestation_object: response["attestationObject"]
          )
        }.to raise_error(OpenPasskey::WebAuthnError) { |e|
          expect(e.code).to eq(expected["error"])
        }
      end
    end
  end
end
