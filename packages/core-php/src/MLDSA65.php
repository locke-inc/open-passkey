<?php

declare(strict_types=1);

namespace OpenPasskey;

class MLDSA65
{
    private static ?\FFI $ffi = null;
    private static mixed $sigCtx = null;

    private static function init(): void
    {
        if (self::$ffi !== null) {
            return;
        }

        if (!extension_loaded('ffi')) {
            throw new \RuntimeException(
                'ML-DSA-65 verification requires the FFI extension and liboqs. '
                . 'Enable ffi in php.ini and install liboqs.'
            );
        }

        $libPath = self::findLibrary();

        self::$ffi = \FFI::cdef(<<<'C'
            typedef int OQS_STATUS;
            typedef struct OQS_SIG OQS_SIG;
            void OQS_init(void);
            OQS_SIG *OQS_SIG_new(const char *method_name);
            OQS_STATUS OQS_SIG_verify(
                const OQS_SIG *sig,
                const uint8_t *message,
                size_t message_len,
                const uint8_t *signature,
                size_t signature_len,
                const uint8_t *public_key
            );
            void OQS_SIG_free(OQS_SIG *sig);
        C, $libPath);

        self::$ffi->OQS_init();
        self::$sigCtx = self::$ffi->OQS_SIG_new('ML-DSA-65');

        if (\FFI::isNull(self::$sigCtx)) {
            throw new \RuntimeException('ML-DSA-65 algorithm not available in liboqs');
        }
    }

    private static function findLibrary(): string
    {
        $envPath = getenv('LIBOQS_PATH');
        if ($envPath !== false && $envPath !== '') {
            return $envPath;
        }

        $candidates = PHP_OS_FAMILY === 'Darwin'
            ? ['liboqs.dylib', '/opt/homebrew/lib/liboqs.dylib', '/usr/local/lib/liboqs.dylib']
            : ['liboqs.so', '/usr/lib/liboqs.so', '/usr/lib/x86_64-linux-gnu/liboqs.so', '/usr/local/lib/liboqs.so'];

        $oqsInstall = getenv('OQS_INSTALL_PATH');
        if ($oqsInstall !== false && $oqsInstall !== '') {
            $ext = PHP_OS_FAMILY === 'Darwin' ? 'dylib' : 'so';
            array_unshift($candidates, $oqsInstall . "/lib/liboqs.{$ext}");
        }

        foreach ($candidates as $path) {
            if (!str_contains($path, '/')) {
                return $path;
            }
            if (file_exists($path)) {
                return $path;
            }
        }

        return PHP_OS_FAMILY === 'Darwin' ? 'liboqs.dylib' : 'liboqs.so';
    }

    public static function verify(string $coseKeyData, string $authData, string $clientDataJSON, string $signature): void
    {
        self::init();

        $map = CborDecoder::decode($coseKeyData);

        $kty = $map[1] ?? null;
        $alg = $map[3] ?? null;
        $pub = $map[-1] ?? null;

        if ($kty !== Cose::KTY_MLDSA || $alg !== Cose::ALG_MLDSA65) {
            throw new WebAuthnException('unsupported_cose_algorithm');
        }

        if (strlen($pub) !== Cose::MLDSA_PUB_KEY_SIZE) {
            throw new WebAuthnException('unsupported_cose_algorithm', 'ML-DSA-65 public key wrong length');
        }

        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $verifyData = $authData . $clientDataHash;

        self::verifyRaw($pub, $verifyData, $signature);
    }

    public static function verifyRaw(string $publicKey, string $message, string $signature): void
    {
        self::init();

        $msgLen = strlen($message);
        $sigLen = strlen($signature);

        $msgBuf = self::$ffi->new("uint8_t[{$msgLen}]");
        \FFI::memcpy($msgBuf, $message, $msgLen);

        $sigBuf = self::$ffi->new("uint8_t[{$sigLen}]");
        \FFI::memcpy($sigBuf, $signature, $sigLen);

        $keyBuf = self::$ffi->new('uint8_t[' . Cose::MLDSA_PUB_KEY_SIZE . ']');
        \FFI::memcpy($keyBuf, $publicKey, Cose::MLDSA_PUB_KEY_SIZE);

        $result = self::$ffi->OQS_SIG_verify(
            self::$sigCtx,
            $msgBuf,
            $msgLen,
            $sigBuf,
            $sigLen,
            $keyBuf,
        );

        if ($result !== 0) {
            throw new WebAuthnException('signature_invalid');
        }
    }
}
