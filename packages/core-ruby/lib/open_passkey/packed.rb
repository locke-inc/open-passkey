# frozen_string_literal: true

module OpenPasskey
  module Packed
    class << self
      def verify(att_stmt, auth_data, client_data_json_raw, credential_key)
        if att_stmt["x5c"]
          verify_full_attestation(att_stmt, auth_data, client_data_json_raw)
        else
          Signature.verify(credential_key, auth_data, client_data_json_raw, att_stmt["sig"])
        end
      end

      private

      def verify_full_attestation(att_stmt, auth_data, client_data_json_raw)
        x5c = att_stmt["x5c"]
        if x5c.nil? || x5c.empty?
          raise WebAuthnError.new("invalid_attestation_statement", "x5c is empty")
        end

        cert_der = x5c[0]
        cert = OpenSSL::X509::Certificate.new(cert_der)
        pub_key = cert.public_key

        alg = att_stmt["alg"]
        unless alg == Cose::ALG_ES256
          raise WebAuthnError.new("unsupported_cose_algorithm", "Attestation alg #{alg}")
        end

        client_data_hash = OpenSSL::Digest::SHA256.digest(client_data_json_raw)
        verify_data = auth_data + client_data_hash

        result = pub_key.verify("SHA256", att_stmt["sig"], verify_data)
        raise WebAuthnError.new("signature_invalid") unless result
      rescue OpenSSL::X509::CertificateError
        raise WebAuthnError.new("signature_invalid", "Failed to parse attestation certificate")
      rescue OpenSSL::PKey::PKeyError
        raise WebAuthnError.new("signature_invalid")
      end
    end
  end
end
