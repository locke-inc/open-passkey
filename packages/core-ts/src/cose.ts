// COSE algorithm identifiers (IANA registry).
// https://www.iana.org/assignments/cose/cose.xhtml

/** ECDSA w/ SHA-256 on P-256 (classical) */
export const COSE_ALG_ES256 = -7;

/** ML-DSA-65 / Dilithium3 (post-quantum, FIPS 204) */
export const COSE_ALG_MLDSA65 = -49;

/** ML-DSA-65-ES256 composite (hybrid PQ, draft-ietf-jose-pq-composite-sigs) */
export const COSE_ALG_COMPOSITE_MLDSA65_ES256 = -52;

// COSE key type identifiers.

/** Elliptic Curve (two coordinates) */
export const COSE_KTY_EC2 = 2;

/** ML-DSA (Module-Lattice Digital Signature) */
export const COSE_KTY_MLDSA = 8;

/** Composite key (draft-ietf-jose-pq-composite-sigs) */
export const COSE_KTY_COMPOSITE = 9;
