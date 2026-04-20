# frozen_string_literal: true

require "openssl"
require "digest"

module OpenPasskey
  module ES256
    class << self
      def verify(cose_key_data, auth_data, client_data_json, signature)
        pem_key = decode_cose_key(cose_key_data)
        verify_with_key(pem_key, auth_data, client_data_json, signature)
      end

      def verify_with_key(pkey, auth_data, client_data_json, signature)
        client_data_hash = OpenSSL::Digest::SHA256.digest(client_data_json)
        verify_data = auth_data + client_data_hash
        verify_with_raw_hash(pkey, verify_data, signature)
      end

      def verify_with_raw_hash(pkey, verify_data, signature)
        result = pkey.verify("SHA256", signature, verify_data)
        raise WebAuthnError.new("signature_invalid") unless result
      rescue OpenSSL::PKey::PKeyError
        raise WebAuthnError.new("signature_invalid")
      end

      def decode_cose_key(data)
        map = CborDecoder.decode(data)

        kty = map[1]
        alg = map[3]
        crv = map[-1]
        x = map[-2]
        y = map[-3]

        unless kty == Cose::KTY_EC2 && alg == Cose::ALG_ES256 && crv == 1
          raise WebAuthnError.new("unsupported_cose_algorithm")
        end
        unless x.is_a?(String) && y.is_a?(String) && x.bytesize == 32 && y.bytesize == 32
          raise WebAuthnError.new("unsupported_cose_algorithm", "Invalid EC2 key coordinate length")
        end

        raw_to_pkey(x, y)
      end

      def raw_to_pkey(x, y)
        uncompressed = "\x04".b + x.b + y.b

        group = OpenSSL::PKey::EC::Group.new("prime256v1")
        point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(uncompressed, 2))

        asn1 = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
            OpenSSL::ASN1::ObjectId.new("prime256v1"),
          ]),
          OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed)),
        ])

        OpenSSL::PKey::EC.new(asn1.to_der)
      end
    end
  end
end
