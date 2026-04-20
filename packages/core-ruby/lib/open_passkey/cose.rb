# frozen_string_literal: true

module OpenPasskey
  module Cose
    ALG_ES256 = -7
    ALG_MLDSA65 = -49
    ALG_COMPOSITE_MLDSA65_ES256 = -52

    KTY_EC2 = 2
    KTY_MLDSA = 8
    KTY_COMPOSITE = 9

    MLDSA_PUB_KEY_SIZE = 1952
    ECDSA_UNCOMPRESSED_SIZE = 65
  end
end
