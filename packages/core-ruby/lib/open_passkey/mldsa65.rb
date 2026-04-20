# frozen_string_literal: true

require "ffi"

module OpenPasskey
  module MLDSA65
    extend FFI::Library

    ALGORITHM_NAME = "ML-DSA-65"

    class << self
      def verify(cose_key_data, auth_data, client_data_json, signature)
        map = CborDecoder.decode(cose_key_data)

        kty = map[1]
        alg = map[3]
        pub = map[-1]

        unless kty == Cose::KTY_MLDSA && alg == Cose::ALG_MLDSA65
          raise WebAuthnError.new("unsupported_cose_algorithm")
        end

        unless pub.is_a?(String) && pub.bytesize == Cose::MLDSA_PUB_KEY_SIZE
          raise WebAuthnError.new("unsupported_cose_algorithm", "ML-DSA-65 public key wrong length")
        end

        client_data_hash = OpenSSL::Digest::SHA256.digest(client_data_json)
        verify_data = auth_data + client_data_hash

        verify_raw(pub, verify_data, signature)
      end

      def verify_raw(public_key, message, signature)
        ensure_loaded!

        msg_ptr = FFI::MemoryPointer.new(:uint8, message.bytesize)
        msg_ptr.put_bytes(0, message)

        sig_ptr = FFI::MemoryPointer.new(:uint8, signature.bytesize)
        sig_ptr.put_bytes(0, signature)

        key_ptr = FFI::MemoryPointer.new(:uint8, Cose::MLDSA_PUB_KEY_SIZE)
        key_ptr.put_bytes(0, public_key)

        result = OqsBindings.oqs_sig_verify(
          @sig_ctx,
          msg_ptr, message.bytesize,
          sig_ptr, signature.bytesize,
          key_ptr
        )

        raise WebAuthnError.new("signature_invalid") unless result == 0
      end

      private

      def ensure_loaded!
        return if @loaded

        lib_path = find_library

        OqsBindings.module_eval do
          extend FFI::Library
          ffi_lib lib_path
          attach_function :oqs_init, :OQS_init, [], :void
          attach_function :oqs_sig_new, :OQS_SIG_new, [:string], :pointer
          attach_function :oqs_sig_verify, :OQS_SIG_verify,
            [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer], :int
          attach_function :oqs_sig_free, :OQS_SIG_free, [:pointer], :void
        end

        OqsBindings.oqs_init
        @sig_ctx = OqsBindings.oqs_sig_new(ALGORITHM_NAME)

        if @sig_ctx.null?
          raise RuntimeError, "ML-DSA-65 algorithm not available in liboqs"
        end

        @loaded = true
      end

      def find_library
        env_path = ENV["LIBOQS_PATH"]
        return env_path if env_path && !env_path.empty?

        candidates = if RUBY_PLATFORM.include?("darwin")
          ["liboqs.dylib", "/opt/homebrew/lib/liboqs.dylib", "/usr/local/lib/liboqs.dylib"]
        else
          ["liboqs.so", "/usr/lib/liboqs.so", "/usr/lib/x86_64-linux-gnu/liboqs.so", "/usr/local/lib/liboqs.so"]
        end

        oqs_install = ENV["OQS_INSTALL_PATH"]
        if oqs_install && !oqs_install.empty?
          ext = RUBY_PLATFORM.include?("darwin") ? "dylib" : "so"
          candidates.unshift("#{oqs_install}/lib/liboqs.#{ext}")
        end

        candidates.each do |path|
          return path unless path.include?("/")
          return path if File.exist?(path)
        end

        RUBY_PLATFORM.include?("darwin") ? "liboqs.dylib" : "liboqs.so"
      end
    end

    module OqsBindings
    end
  end
end
