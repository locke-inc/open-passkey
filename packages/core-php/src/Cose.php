<?php

declare(strict_types=1);

namespace OpenPasskey;

class Cose
{
    public const ALG_ES256 = -7;
    public const ALG_MLDSA65 = -49;
    public const ALG_COMPOSITE_MLDSA65_ES256 = -52;

    public const KTY_EC2 = 2;
    public const KTY_MLDSA = 8;
    public const KTY_COMPOSITE = 9;

    public const MLDSA_PUB_KEY_SIZE = 1952;
    public const ECDSA_UNCOMPRESSED_SIZE = 65;
}
