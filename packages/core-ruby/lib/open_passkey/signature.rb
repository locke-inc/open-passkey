# frozen_string_literal: true

module OpenPasskey
  module Signature
    class << self
      def verify(cose_key_data, auth_data, client_data_json, signature)
        alg = identify_algorithm(cose_key_data)

        case alg
        when Cose::ALG_ES256
          ES256.verify(cose_key_data, auth_data, client_data_json, signature)
        when Cose::ALG_MLDSA65
          MLDSA65.verify(cose_key_data, auth_data, client_data_json, signature)
        when Cose::ALG_COMPOSITE_MLDSA65_ES256
          Composite.verify(cose_key_data, auth_data, client_data_json, signature)
        else
          raise WebAuthnError.new("unsupported_cose_algorithm")
        end
      end

      private

      def identify_algorithm(data)
        map = CborDecoder.decode(data)
        alg = map[3]
        raise WebAuthnError.new("unsupported_cose_algorithm") unless alg
        alg
      end
    end
  end
end
