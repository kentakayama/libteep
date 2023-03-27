#ifndef EAT_H
#define EAT_H

typedef enum eat_claim_key {
    EAT_CLAIM_ISSUER            = 1, /* iss */
    EAT_CLAIM_EXP               = 4, /* exp */
    EAT_CLAIM_NOT_BEFORE        = 5, /* nbf */
    EAT_CLAIM_TIMESTAMP         = 6, /* iat */
    EAT_CLAIM_CONFIRMATION      = 8, /* cnf */
    EAT_CLAIM_EAT_NONCE         = 10,
    EAT_CLAIM_NONCE             = 10, /* XXX: to be removed */
    EAT_CLAIM_SECURE_BOOT       = 15, /* XXX: removed? */
    EAT_CLAIM_DEBUG_STATUS      = 16, /* XXX: removed? */
    EAT_CLAIM_CHIP_VERSION      = 26, /* XXX: removed? */
    EAT_CLAIM_UEID              = 256,
    EAT_CLAIM_SUEIDS            = 257,
    EAT_CLAIM_OEMID             = 258,
    EAT_CLAIM_HWMODEL           = 259,
    EAT_CLAIM_HWVERSION         = 260,
    EAT_CLAIM_OEMBOOT           = 262,
    EAT_CLAIM_DBGSTAT           = 263,
    EAT_CLAIM_LOCATION          = 264,
    EAT_CLAIM_EAT_PROFILE       = 265,
    EAT_CLAIM_SUBMODS           = 266,
    EAT_CLAIM_SWNAME            = 271,
    EAT_CLAIM_SWVERSION         = 272,
    EAT_CLAIM_MANIFESTS         = 273,
    EAT_CLAIM_MEASUREMENTS      = 274,
    EAT_CLAIM_VERIFIER_NONCE    = -70000,
} eat_claim_key_t;

enum eat_claim_cnf_key {
    EAT_CLAIM_CONFIRMATION_COSE_KEY             = 1,
    EAT_CLAIM_CONFIRMATION_ENCRYPTED_COSE_KEY   = 2,
    EAT_CLAIM_CONFIRMATION_KID                  = 3,
};
#endif /* EAT_H */
