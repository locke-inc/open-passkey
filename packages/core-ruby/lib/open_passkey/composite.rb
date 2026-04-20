# frozen_string_literal: true

module OpenPasskey
  module Composite
    class << self
      def verify(cose_key_data, auth_data, client_data_json, signature)
        map = CborDecoder.decode(cose_key_data)

        kty = map[1]
        alg = map[3]
        pub = map[-1]

        unless kty == Cose::KTY_COMPOSITE && alg == Cose::ALG_COMPOSITE_MLDSA65_ES256
          raise WebAuthnError.new("unsupported_cose_algorithm")
        end

        expected_len = Cose::MLDSA_PUB_KEY_SIZE + Cose::ECDSA_UNCOMPRESSED_SIZE
        unless pub.is_a?(String) && pub.bytesize == expected_len
          raise WebAuthnError.new("unsupported_cose_algorithm", "Composite public key wrong length")
        end

        mldsa_pub = pub.byteslice(0, Cose::MLDSA_PUB_KEY_SIZE)
        ecdsa_pub = pub.byteslice(Cose::MLDSA_PUB_KEY_SIZE, Cose::ECDSA_UNCOMPRESSED_SIZE)

        unless ecdsa_pub.getbyte(0) == 0x04
          raise WebAuthnError.new("unsupported_cose_algorithm", "ECDSA component not uncompressed point")
        end

        if signature.bytesize < 4
          raise WebAuthnError.new("signature_invalid")
        end

        mldsa_sig_len = signature.byteslice(0, 4).unpack1("N")
        if mldsa_sig_len + 4 > signature.bytesize
          raise WebAuthnError.new("signature_invalid")
        end

        mldsa_sig = signature.byteslice(4, mldsa_sig_len)
        ecdsa_sig = signature.byteslice((4 + mldsa_sig_len)..)

        client_data_hash = OpenSSL::Digest::SHA256.digest(client_data_json)
        verify_data = auth_data + client_data_hash

        MLDSA65.verify_raw(mldsa_pub, verify_data, mldsa_sig)

        x = ecdsa_pub.byteslice(1, 32)
        y = ecdsa_pub.byteslice(33, 32)
        pkey = ES256.raw_to_pkey(x, y)
        ES256.verify_with_raw_hash(pkey, verify_data, ecdsa_sig)
      end
    end
  end
end
